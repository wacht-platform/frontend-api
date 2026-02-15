package session

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/pkg/idgen"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type TicketType string

const (
	TicketTypeImpersonation    TicketType = "impersonation"
	TicketTypeAgentAccess      TicketType = "agent_access"
	TicketTypeWebhookAppAccess TicketType = "webhook_app_access"
	TicketTypeApiAuthAccess    TicketType = "api_auth_access"
)

type SessionTicketPayload struct {
	TicketType     TicketType `json:"ticket_type"`
	DeploymentID   string     `json:"deployment_id"`
	UserID         *string    `json:"user_id,omitempty"`
	AgentIDs       []string   `json:"agent_ids,omitempty"`
	WebhookAppSlug *string    `json:"webhook_app_slug,omitempty"`
	ApiAuthAppSlug *string    `json:"api_auth_app_slug,omitempty"`
	ContextGroup   *string    `json:"context_group,omitempty"`
	ExpiresAt      int64      `json:"expires_at"`
}

type ExchangeTicketRequest struct {
	Ticket string `query:"ticket"`
}

type AgentInfo struct {
	ID           string                   `json:"id"`
	Name         string                   `json:"name"`
	Description  string                   `json:"description"`
	Integrations []model.AgentIntegration `json:"integrations"`
}

type WebhookAppInfo struct {
	AppSlug       string `json:"app_slug"`
	Name          string `json:"name"`
	SigningSecret string `json:"signing_secret"`
	IsActive      bool   `json:"is_active"`
}

type ApiAuthAppInfo struct {
	ID          string           `json:"id"`
	AppSlug     string           `json:"app_slug"`
	Name        string           `json:"name"`
	Description *string          `json:"description,omitempty"`
	IsActive    bool             `json:"is_active"`
	RateLimits  model.RateLimits `json:"rate_limits"`
}

type ExchangeTicketResponse struct {
	Success      bool            `json:"success"`
	Message      string          `json:"message,omitempty"`
	SessionID    *string         `json:"session_id,omitempty"`
	ContextGroup *string         `json:"context_group,omitempty"`
	Agents       []AgentInfo     `json:"agents,omitempty"`
	WebhookApp   *WebhookAppInfo `json:"webhook_app,omitempty"`
	ApiAuthApp   *ApiAuthAppInfo `json:"api_auth_app,omitempty"`
	Session      *model.Session  `json:"session,omitempty"`
}

func (h *Handler) ExchangeTicket(c *fiber.Ctx) error {
	ticket := c.Query("ticket")
	if ticket == "" {
		return handler.SendBadRequest(c, nil, "ticket is required")
	}

	redisKey := fmt.Sprintf("session:ticket:%s", ticket)
	ticketJSON, err := database.Redis.Get(c.Context(), redisKey).Result()
	if err != nil {
		return handler.SendUnauthorized(c, nil, "Invalid or expired ticket")
	}

	var payload SessionTicketPayload
	if err := json.Unmarshal([]byte(ticketJSON), &payload); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to parse ticket")
	}

	// Verify deployment
	deployment := handler.GetDeployment(c)
	deploymentID, err := strconv.ParseUint(payload.DeploymentID, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, err, "Invalid deployment ID in ticket")
	}
	if deploymentID != deployment.ID {
		return handler.SendUnauthorized(c, nil, "Ticket not valid for this deployment")
	}

	// Handle based on ticket type
	switch payload.TicketType {
	case TicketTypeImpersonation:
		return h.handleImpersonationExchange(c, &payload, &deployment, ticket)
	case TicketTypeAgentAccess:
		return h.handleAgentAccessExchange(c, &payload, &deployment, ticket)
	case TicketTypeWebhookAppAccess:
		return h.handleWebhookAppAccessExchange(c, &payload, &deployment, ticket)
	case TicketTypeApiAuthAccess:
		return h.handleApiAuthAccessExchange(c, &payload, &deployment, ticket)
	default:
		return handler.SendBadRequest(c, nil, "Invalid ticket type")
	}
}

func (h *Handler) handleImpersonationExchange(
	c *fiber.Ctx,
	payload *SessionTicketPayload,
	deployment *model.Deployment,
	ticket string,
) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Session required")
	}

	// Validate required fields
	if payload.UserID == nil {
		return handler.SendBadRequest(c, nil, "user_id is required for impersonation tickets")
	}

	userID, err := strconv.ParseUint(*payload.UserID, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, err, "Invalid user_id")
	}

	// Check user exists and is not disabled
	var user model.User
	if err := database.Connection.Where("id = ? AND deployment_id = ?", userID, deployment.ID).
		First(&user).Error; err != nil {
		return handler.SendNotFound(c, nil, "User not found")
	}

	if user.Disabled {
		return handler.SendForbidden(c, nil, "Cannot impersonate disabled user")
	}

	// Check user isn't already signed in
	for _, signIn := range session.Signins {
		if signIn.UserID != nil && *signIn.UserID == userID {
			return handler.SendBadRequest(
				c,
				nil,
				"User already signed in",
			)
		}
	}

	steps := []model.SignInAttemptStep{}
	attempt := h.createSignInAttempt(&userID, session.ID, steps)
	attempt.FirstMethodAuthenticated = true

	var signIn *model.Signin
	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(attempt).Error; err != nil {
			return err
		}

		signIn = h.createSignIn(&userID, session.ID, 1200)
		if err := tx.Create(signIn).Error; err != nil {
			return err
		}

		if err := tx.Model(&model.Session{}).Where("id = ?", session.ID).
			Update("active_signin_id", signIn.ID).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.ConstraintName == "idx_session_user_id" {
			return handler.SendBadRequest(
				c,
				nil,
				"User already signed in",
			)
		}
		return handler.SendInternalServerError(c, err, "Failed to create session")
	}

	// Delete ticket from Redis (single-use enforcement)
	redisKey := fmt.Sprintf("session:ticket:%s", ticket)
	if err := database.Redis.Del(c.Context(), redisKey).Err(); err != nil {
		// Log error but don't fail the request
		fmt.Printf("Warning: Failed to delete ticket after exchange: %v\n", err)
	}

	// Publish event
	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess(c, ExchangeTicketResponse{
		Success: true,
		Message: "Impersonation successful",
		Session: session,
	})
}

func (h *Handler) handleAgentAccessExchange(
	c *fiber.Ctx,
	payload *SessionTicketPayload,
	deployment *model.Deployment,
	ticket string,
) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Session required")
	}

	// Validate required fields
	if payload.AgentIDs == nil || len(payload.AgentIDs) == 0 {
		return handler.SendBadRequest(c, nil, "agent_ids is required for agent_access tickets")
	}

	// Parse agent IDs
	agentIDs := make([]int64, len(payload.AgentIDs))
	for i, idStr := range payload.AgentIDs {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			return handler.SendBadRequest(c, err, fmt.Sprintf("Invalid agent_id: %s", idStr))
		}
		agentIDs[i] = id
	}

	// Determine context group
	var contextGroup string
	if payload.ContextGroup != nil && *payload.ContextGroup != "" {
		contextGroup = *payload.ContextGroup
	} else {
		return handler.SendBadRequest(c, nil, "context_group is required for agent_access tickets")
	}

	// Calculate expiration
	var expiresAt *time.Time
	if payload.ExpiresAt > 0 {
		t := time.Unix(payload.ExpiresAt, 0)
		expiresAt = &t
	}

	// Expire old agent sessions for this session
	now := time.Now()
	if err := database.Connection.Model(&model.AgentSession{}).
		Where("session_id = ? AND (expires_at IS NULL OR expires_at > ?)", session.ID, now).
		Update("expires_at", now).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to expire old sessions")
	}

	// Create new AgentSession
	agentSession := model.NewAgentSession(
		session.ID,
		deployment.ID,
		model.AgentSessionIdentifierStatic,
		contextGroup,
		agentIDs,
		expiresAt,
	)

	if err := database.Connection.Create(agentSession).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create agent session")
	}

	agents, err := h.getAllowlistedAgents(deployment.ID, agentIDs)
	if err != nil {
		return handler.SendInternalServerError(c, err, err.Error())
	}

	// Delete ticket from Redis (single-use enforcement)
	redisKey := fmt.Sprintf("session:ticket:%s", ticket)
	if err := database.Redis.Del(c.Context(), redisKey).Err(); err != nil {
		fmt.Printf("Warning: Failed to delete ticket after exchange: %v\n", err)
	}

	return handler.SendSuccess(c, ExchangeTicketResponse{
		Success:      true,
		Message:      "Agent session created",
		SessionID:    ptr(strconv.FormatUint(agentSession.ID, 10)),
		ContextGroup: &contextGroup,
		Agents:       agents,
	})
}

func (h *Handler) createSignInAttempt(
	userID *uint64,
	sessionID uint64,
	steps []model.SignInAttemptStep,
) *model.SignInAttempt {
	attempt := model.NewSignInAttempt(model.SignInMethodImpersonation)
	if len(steps) > 0 {
		attempt.CurrentStep = steps[0]
	}
	attempt.RemainingSteps = datatypes.NewJSONSlice(steps)
	attempt.UserID = userID
	attempt.SessionID = sessionID
	attempt.Completed = true
	return attempt
}

func (h *Handler) createSignIn(
	userID *uint64,
	sessionID uint64,
	expiresInSec uint64,
) *model.Signin {
	return &model.Signin{
		Model: model.Model{
			ID: idgen.NextID(),
		},
		UserID:    userID,
		SessionID: sessionID,
		ExpiresAt: time.Now().Add(time.Duration(expiresInSec) * time.Second),
	}
}

func (h *Handler) getAllowlistedAgents(deploymentID uint64, agentIDs []int64) ([]AgentInfo, error) {
	var agents []model.AiAgent
	if err := database.Connection.
		Where("deployment_id = ? AND id IN ?", deploymentID, agentIDs).
		Find(&agents).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch agents: %w", err)
	}

	var result []AgentInfo

	for _, agent := range agents {
		var integrations []model.AgentIntegration
		if err := database.Connection.
			Where("deployment_id = ? AND agent_id = ?", deploymentID, agent.ID).
			Find(&integrations).Error; err != nil {
			return nil, fmt.Errorf("failed to fetch integrations for agent %d: %w", agent.ID, err)
		}

		result = append(result, AgentInfo{
			ID:           fmt.Sprintf("%d", agent.ID),
			Name:         agent.Name,
			Description:  agent.Description,
			Integrations: integrations,
		})
	}

	return result, nil
}

func (h *Handler) handleWebhookAppAccessExchange(
	c *fiber.Ctx,
	payload *SessionTicketPayload,
	deployment *model.Deployment,
	ticket string,
) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Session required")
	}

	if payload.WebhookAppSlug == nil || *payload.WebhookAppSlug == "" {
		return handler.SendBadRequest(c, nil, "webhook_app_slug is required for webhook_app_access tickets")
	}

	appSlug := *payload.WebhookAppSlug

	// Calculate expiration
	var expiresAt *time.Time
	if payload.ExpiresAt > 0 {
		t := time.Unix(payload.ExpiresAt, 0)
		expiresAt = &t
	}

	now := time.Now()
	if err := database.Connection.Model(&model.WebhookAppSession{}).
		Where("session_id = ? AND app_slug = ? AND (expires_at IS NULL OR expires_at > ?)", session.ID, appSlug, now).
		Update("expires_at", now).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to expire old sessions")
	}

	webhookAppSession := model.NewWebhookAppSession(
		session.ID,
		deployment.ID,
		appSlug,
		expiresAt,
	)

	if err := database.Connection.Create(webhookAppSession).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create webhook app session")
	}

	webhookApp, err := h.getWebhookApp(deployment.ID, appSlug)
	if err != nil {
		return handler.SendInternalServerError(c, err, err.Error())
	}

	redisKey := fmt.Sprintf("session:ticket:%s", ticket)
	if err := database.Redis.Del(c.Context(), redisKey).Err(); err != nil {
		fmt.Printf("Warning: Failed to delete ticket after exchange: %v\n", err)
	}

	return handler.SendSuccess(c, ExchangeTicketResponse{
		Success:    true,
		Message:    "Webhook app session created",
		SessionID:  ptr(strconv.FormatUint(webhookAppSession.ID, 10)),
		WebhookApp: webhookApp,
	})
}

func (h *Handler) getWebhookApp(deploymentID uint64, appSlug string) (*WebhookAppInfo, error) {
	var app model.WebhookApp
	err := database.Connection.
		Where("deployment_id = ? AND app_slug = ?", deploymentID, appSlug).
		First(&app).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("webhook app not found")
		}
		return nil, fmt.Errorf("failed to fetch webhook app: %w", err)
	}

	return &WebhookAppInfo{
		AppSlug:       app.AppSlug,
		Name:          app.Name,
		SigningSecret: app.SigningSecret,
		IsActive:      app.IsActive,
	}, nil
}

func (h *Handler) handleApiAuthAccessExchange(
	c *fiber.Ctx,
	payload *SessionTicketPayload,
	deployment *model.Deployment,
	ticket string,
) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Session required")
	}

	if payload.ApiAuthAppSlug == nil || *payload.ApiAuthAppSlug == "" {
		return handler.SendBadRequest(c, nil, "api_auth_app_slug is required for api_auth_access tickets")
	}

	appSlug := *payload.ApiAuthAppSlug

	var expiresAt *time.Time
	if payload.ExpiresAt > 0 {
		t := time.Unix(payload.ExpiresAt, 0)
		expiresAt = &t
	}

	now := time.Now()
	if err := database.Connection.Model(&model.ApiAuthAppSession{}).
		Where("session_id = ? AND app_slug = ? AND (expires_at IS NULL OR expires_at > ?)", session.ID, appSlug, now).
		Update("expires_at", now).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to expire old sessions")
	}

	apiAuthAppSession := model.NewApiAuthAppSession(
		session.ID,
		deployment.ID,
		appSlug,
		expiresAt,
	)

	if err := database.Connection.Create(apiAuthAppSession).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create API auth app session")
	}

	apiAuthApp, err := h.getApiAuthApp(deployment.ID, appSlug)
	if err != nil {
		return handler.SendInternalServerError(c, err, err.Error())
	}

	redisKey := fmt.Sprintf("session:ticket:%s", ticket)
	if err := database.Redis.Del(c.Context(), redisKey).Err(); err != nil {
		fmt.Printf("Warning: Failed to delete ticket after exchange: %v\n", err)
	}

	return handler.SendSuccess(c, ExchangeTicketResponse{
		Success:    true,
		Message:    "API auth app session created",
		SessionID:  ptr(strconv.FormatUint(apiAuthAppSession.ID, 10)),
		ApiAuthApp: apiAuthApp,
	})
}

func (h *Handler) getApiAuthApp(deploymentID uint64, appSlug string) (*ApiAuthAppInfo, error) {
	var app model.ApiAuthApp
	err := database.Connection.
		Where("deployment_id = ? AND app_slug = ? AND deleted_at IS NULL", deploymentID, appSlug).
		First(&app).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("API auth app not found")
		}
		return nil, fmt.Errorf("failed to fetch API auth app: %w", err)
	}

	return &ApiAuthAppInfo{
		ID:          appSlug,
		AppSlug:     app.AppSlug,
		Name:        app.Name,
		Description: app.Description,
		IsActive:    app.IsActive,
		RateLimits:  app.RateLimits,
	}, nil
}

func ptr[T any](v T) *T {
	return &v
}
