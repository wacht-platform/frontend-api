package external_connection

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/wacht-platform/frontend-api/config"
	"github.com/wacht-platform/frontend-api/database"
	"gorm.io/gorm"
)

const composioAPIBase = "https://backend.composio.dev"

// EnabledApp captures the deployment-level enabled-app snapshot stored as JSONB
// on deployment_ai_settings.composio_enabled_apps.
type EnabledApp struct {
	Slug          string `json:"slug"`
	AuthConfigID  string `json:"auth_config_id"`
	DisplayName   string `json:"display_name,omitempty"`
	LogoURL       string `json:"logo_url,omitempty"`
}

type composioSettingsRow struct {
	Enabled         bool    `gorm:"column:composio_enabled"`
	UsePlatformKey  bool    `gorm:"column:composio_use_platform_key"`
	APIKey          *string `gorm:"column:composio_api_key"`
	EnabledAppsJSON []byte  `gorm:"column:composio_enabled_apps;type:jsonb"`
}

type composioDeploymentSettings struct {
	Enabled      bool
	APIKey       string
	EnabledApps  []EnabledApp
}

func loadComposioSettings(deploymentID uint64) (*composioDeploymentSettings, error) {
	var row composioSettingsRow
	if err := database.Connection.Table("deployment_ai_settings").
		Select([]string{
			"composio_enabled",
			"composio_use_platform_key",
			"composio_api_key",
			"composio_enabled_apps",
		}).
		Where("deployment_id = ?", deploymentID).
		Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("composio is not configured for this deployment")
		}
		return nil, err
	}

	var apps []EnabledApp
	if len(row.EnabledAppsJSON) > 0 {
		_ = json.Unmarshal(row.EnabledAppsJSON, &apps)
	}

	apiKey := ""
	if row.UsePlatformKey {
		apiKey = strings.TrimSpace(config.GetEnv("COMPOSIO_PLATFORM_API_KEY", ""))
		if apiKey == "" {
			return nil, fmt.Errorf("platform-managed Composio key is not configured for this environment")
		}
	} else {
		if row.APIKey == nil || strings.TrimSpace(*row.APIKey) == "" {
			return nil, fmt.Errorf("composio API key is not set for this deployment")
		}
		plain, err := decryptDeploymentSecret(*row.APIKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt composio key: %w", err)
		}
		apiKey = plain
	}

	return &composioDeploymentSettings{
		Enabled:     row.Enabled,
		APIKey:      apiKey,
		EnabledApps: apps,
	}, nil
}

func findEnabledApp(apps []EnabledApp, slug string) *EnabledApp {
	for i := range apps {
		if strings.EqualFold(apps[i].Slug, slug) {
			return &apps[i]
		}
	}
	return nil
}

// composioInitiate calls Composio's POST /connected_accounts/link.
type composioInitiateRequest struct {
	AuthConfigID string `json:"auth_config_id"`
	UserID       string `json:"user_id"`
	CallbackURL  string `json:"callback_url"`
}

type composioInitiateResponse struct {
	RedirectURL        string `json:"redirect_url"`
	ConnectedAccountID string `json:"connected_account_id"`
	Nanoid             string `json:"nanoid"`
	ID                 string `json:"id"`
}

func composioInitiate(apiKey, authConfigID, userID, callbackURL string) (redirectURL, connectedAccountID string, err error) {
	body, err := json.Marshal(composioInitiateRequest{
		AuthConfigID: authConfigID,
		UserID:       userID,
		CallbackURL:  callbackURL,
	})
	if err != nil {
		return "", "", err
	}

	req, err := http.NewRequest(http.MethodPost, composioAPIBase+"/api/v3/connected_accounts/link", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("composio initiate returned %d: %s", resp.StatusCode, string(respBody))
	}

	var parsed composioInitiateResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", "", fmt.Errorf("composio initiate parse: %w; body: %s", err, string(respBody))
	}
	id := parsed.ConnectedAccountID
	if id == "" {
		id = parsed.ID
	}
	if id == "" {
		id = parsed.Nanoid
	}
	if parsed.RedirectURL == "" || id == "" {
		return "", "", fmt.Errorf("composio initiate missing fields: %s", string(respBody))
	}
	return parsed.RedirectURL, id, nil
}

func composioDeleteConnectedAccount(apiKey, connectedAccountID string) error {
	if connectedAccountID == "" {
		return nil
	}
	req, err := http.NewRequest(http.MethodDelete,
		composioAPIBase+"/api/v3/connected_accounts/"+connectedAccountID, nil)
	if err != nil {
		return err
	}
	req.Header.Set("x-api-key", apiKey)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("composio delete returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}
