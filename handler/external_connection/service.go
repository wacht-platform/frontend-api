package external_connection

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Service struct{}

func NewService() *Service { return &Service{} }

// GetActiveAgentSession resolves a session+deployment to an agent session (which
// carries the actor_id). Mirrors handler/ai/service.go's matching helper.
func (s *Service) GetActiveAgentSession(sessionID, deploymentID uint64) (*model.AgentSession, error) {
	var agentSession model.AgentSession
	err := database.Connection.Where(
		"session_id = ? AND deployment_id = ? AND (expires_at IS NULL OR expires_at > ?)",
		sessionID, deploymentID, time.Now(),
	).First(&agentSession).Error
	if err != nil {
		return nil, err
	}
	return &agentSession, nil
}

type ConnectionView struct {
	Provider          string     `json:"provider"`
	Slug              string     `json:"slug"`
	DisplayName       string     `json:"display_name"`
	LogoURL           string     `json:"logo_url,omitempty"`
	Status            string     `json:"status"`
	ExternalAccountID string     `json:"external_account_id,omitempty"`
	ConnectedAt       *time.Time `json:"connected_at,omitempty"`
}

// List returns the deployment's enabled apps joined with the actor's connection
// status. Every enabled app appears, with status="disconnected" if the actor
// hasn't linked it yet.
func (s *Service) List(deploymentID, actorID uint64) ([]ConnectionView, error) {
	composioSettings, err := loadComposioSettings(deploymentID)
	if err != nil {
		// Composio not configured or disabled — return empty rather than erroring.
		return []ConnectionView{}, nil
	}
	if !composioSettings.Enabled {
		return []ConnectionView{}, nil
	}

	rows := []model.ActorExternalConnection{}
	if err := database.Connection.
		Where("deployment_id = ? AND actor_id = ? AND provider = ?", deploymentID, actorID, model.ExternalConnectionProviderComposio).
		Find(&rows).Error; err != nil {
		return nil, err
	}
	byKey := map[string]model.ActorExternalConnection{}
	for _, r := range rows {
		byKey[r.Provider+"/"+strings.ToLower(r.Slug)] = r
	}

	views := make([]ConnectionView, 0, len(composioSettings.EnabledApps))
	for _, app := range composioSettings.EnabledApps {
		key := model.ExternalConnectionProviderComposio + "/" + strings.ToLower(app.Slug)
		view := ConnectionView{
			Provider:    model.ExternalConnectionProviderComposio,
			Slug:        app.Slug,
			DisplayName: app.DisplayName,
			LogoURL:     app.LogoURL,
			Status:      "disconnected",
		}
		if existing, ok := byKey[key]; ok {
			view.Status = existing.Status
			view.ExternalAccountID = existing.ExternalAccountID
			view.ConnectedAt = existing.ConnectedAt
		}
		if view.DisplayName == "" {
			view.DisplayName = app.Slug
		}
		views = append(views, view)
	}
	return views, nil
}

// Connect initiates an OAuth flow for the given provider/slug and returns the
// redirect URL to send the user to.
func (s *Service) Connect(deploymentID, actorID uint64, provider, slug, callbackURL, returnURL string) (string, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	slug = strings.ToLower(strings.TrimSpace(slug))
	if provider != model.ExternalConnectionProviderComposio {
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}

	settings, err := loadComposioSettings(deploymentID)
	if err != nil {
		return "", err
	}
	if !settings.Enabled {
		return "", fmt.Errorf("composio is disabled for this deployment")
	}
	app := findEnabledApp(settings.EnabledApps, slug)
	if app == nil {
		return "", fmt.Errorf("%s is not enabled for this deployment", slug)
	}

	userID := fmt.Sprintf("actor_%d", actorID)
	redirectURL, externalAccountID, err := composioInitiate(settings.APIKey, app.AuthConfigID, userID, callbackURL)
	if err != nil {
		return "", err
	}

	// Upsert a pending row so the callback can match on external_account_id.
	conn := model.ActorExternalConnection{
		DeploymentID:      deploymentID,
		ActorID:           actorID,
		Provider:          provider,
		Slug:              slug,
		ExternalAccountID: externalAccountID,
		Status:            model.ExternalConnectionStatusPending,
		ReturnURL:         returnURL,
	}
	if err := database.Connection.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "deployment_id"}, {Name: "actor_id"}, {Name: "provider"}, {Name: "slug"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"external_account_id", "status", "return_url", "updated_at",
		}),
	}).Create(&conn).Error; err != nil {
		return "", err
	}

	return redirectURL, nil
}

// HandleCallback looks up the pending row by external_account_id, updates status,
// and returns the return URL if one was captured at initiate time.
func (s *Service) HandleCallback(provider, externalAccountID, status string) (returnURL string, err error) {
	provider = strings.ToLower(provider)
	externalAccountID = strings.TrimSpace(externalAccountID)
	if externalAccountID == "" {
		return "", fmt.Errorf("missing connected_account_id")
	}

	var row model.ActorExternalConnection
	if err := database.Connection.
		Where("provider = ? AND external_account_id = ?", provider, externalAccountID).
		Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", fmt.Errorf("unknown connection %s", externalAccountID)
		}
		return "", err
	}

	now := time.Now().UTC()
	newStatus := model.ExternalConnectionStatusFailed
	if strings.EqualFold(status, "success") || strings.EqualFold(status, "active") {
		newStatus = model.ExternalConnectionStatusActive
	}

	updates := map[string]any{
		"status":     newStatus,
		"return_url": "",
		"updated_at": now,
	}
	if newStatus == model.ExternalConnectionStatusActive {
		updates["connected_at"] = now
	}
	if err := database.Connection.Model(&model.ActorExternalConnection{}).
		Where("deployment_id = ? AND actor_id = ? AND provider = ? AND slug = ?",
			row.DeploymentID, row.ActorID, row.Provider, row.Slug).
		Updates(updates).Error; err != nil {
		return "", err
	}
	return row.ReturnURL, nil
}

func (s *Service) Disconnect(deploymentID, actorID uint64, provider, slug string) error {
	provider = strings.ToLower(provider)
	slug = strings.ToLower(slug)
	if provider != model.ExternalConnectionProviderComposio {
		return fmt.Errorf("unsupported provider: %s", provider)
	}

	var row model.ActorExternalConnection
	if err := database.Connection.
		Where("deployment_id = ? AND actor_id = ? AND provider = ? AND slug = ?", deploymentID, actorID, provider, slug).
		Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}

	// Best-effort cleanup on Composio; don't block on failures.
	if settings, err := loadComposioSettings(deploymentID); err == nil {
		_ = composioDeleteConnectedAccount(settings.APIKey, row.ExternalAccountID)
	}

	return database.Connection.
		Where("deployment_id = ? AND actor_id = ? AND provider = ? AND slug = ?", deploymentID, actorID, provider, slug).
		Delete(&model.ActorExternalConnection{}).Error
}
