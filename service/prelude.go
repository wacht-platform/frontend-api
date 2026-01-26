package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ilabs/wacht-fe/config"
)

type PreludeService struct {
	APIKey  string
	BaseURL string
	Client  *http.Client
}

type PreludeTarget struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type PreludeSignals struct {
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type PreludeOptions struct {
	CallbackURL string `json:"callback_url,omitempty"`
	CodeSize    uint16 `json:"code_size,omitempty"`
}

type CreateVerificationRequest struct {
	Target  PreludeTarget   `json:"target"`
	Signals *PreludeSignals `json:"signals,omitempty"`
	Options *PreludeOptions `json:"options,omitempty"`
}

type CreateVerificationResponse struct {
	ID       string   `json:"id"`
	Status   string   `json:"status"`
	Method   string   `json:"method"`
	Reason   string   `json:"reason,omitempty"`
	Channels []string `json:"channels,omitempty"`
}

type CheckVerificationRequest struct {
	Target PreludeTarget `json:"target"`
	Code   string        `json:"code"`
}

type CheckVerificationResponse struct {
	Status string `json:"status"`
	ID     string `json:"id"`
}

var preludeService *PreludeService

func InitPrelude() error {
	apiKey := config.GetEnv("PRELUDE_API_KEY", "")
	if apiKey == "" {
		return fmt.Errorf("PRELUDE_API_KEY not configured")
	}

	preludeService = &PreludeService{
		APIKey:  apiKey,
		BaseURL: "https://api.prelude.dev/v2",
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	return nil
}

func GetPrelude() *PreludeService {
	if preludeService == nil {
		panic("Prelude service not initialized")
	}
	return preludeService
}

func (p *PreludeService) SendVerification(phoneNumber string, deploymentID, userID uint64, clientIP, userAgent string) (*CreateVerificationResponse, error) {
	callbackURL := fmt.Sprintf("%s/webhooks/dodo/%d",
		config.GetEnv("PLATFORM_API_URL", "https://platform.wacht.dev"),
		deploymentID)

	reqBody := CreateVerificationRequest{
		Target: PreludeTarget{
			Type:  "phone_number",
			Value: phoneNumber,
		},
		Signals: &PreludeSignals{
			IP:        clientIP,
			UserAgent: userAgent,
		},
		Options: &PreludeOptions{
			CallbackURL: callbackURL,
			CodeSize:    6,
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", p.BaseURL+"/verification", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prelude API error (status %d): %s", resp.StatusCode, string(body))
	}

	var result CreateVerificationResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Status == "blocked" {
		return nil, fmt.Errorf("verification blocked: %s", result.Reason)
	}

	return &result, nil
}

func (p *PreludeService) CheckVerification(phoneNumber, code string) (bool, error) {
	reqBody := CheckVerificationRequest{
		Target: PreludeTarget{
			Type:  "phone_number",
			Value: phoneNumber,
		},
		Code: code,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return false, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", p.BaseURL+"/verification/check", bytes.NewBuffer(jsonData))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.Client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("prelude API error (status %d): %s", resp.StatusCode, string(body))
	}

	var result CheckVerificationResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Errorf("failed to parse response: %w", err)
	}

	return result.Status == "success", nil
}
