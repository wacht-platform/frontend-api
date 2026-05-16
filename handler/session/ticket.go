package session

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/model"
	"github.com/wacht-platform/frontend-api/pkg/idgen"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

const (
	agentSessionActorSubjectTypeUser = "user"
	defaultActorMetadataJSON         = "{}"
)

type TicketType string

const (
	TicketTypeImpersonation    TicketType = "impersonation"
	TicketTypeAgentAccess      TicketType = "agent_access"
	TicketTypeWebhookAppAccess TicketType = "webhook_app_access"
	TicketTypeApiAuthAccess    TicketType = "api_auth_access"
)

type SessionTicketPayload struct {
	TicketType             TicketType                    `json:"ticket_type"`
	DeploymentID           string                        `json:"deployment_id"`
	UserID                 *string                       `json:"user_id,omitempty"`
	ActorID                *string                       `json:"actor_id,omitempty"`
	AgentIDs               []string                      `json:"agent_ids,omitempty"`
	AgentSessionIdentifier *model.AgentSessionIdentifier `json:"agent_session_identifier,omitempty"`
	WebhookAppSlug         *string                       `json:"webhook_app_slug,omitempty"`
	ApiAuthAppSlug         *string                       `json:"api_auth_app_slug,omitempty"`
	ExpiresAt              int64                         `json:"expires_at"`
}

type ExchangeTicketRequest struct {
	Ticket string `query:"ticket"`
}

type AgentInfo struct {
	ID          uint64      `json:"id,string"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	ChildAgents []AgentInfo `json:"child_agents,omitempty"`
}

type allowlistedAgentRow struct {
	ID          uint64          `gorm:"column:id"`
	Name        string          `gorm:"column:name"`
	Description string          `gorm:"column:description"`
	ChildAgents json.RawMessage `gorm:"column:child_agents"`
}

type hydratedSessionExchangeRow struct {
	SessionID uint64          `gorm:"column:session_id"`
	Actor     json.RawMessage `gorm:"column:actor"`
	Agents    json.RawMessage `gorm:"column:agents"`
}

type ActorInfo struct {
	ID          uint64  `json:"id,string"`
	DisplayName *string `json:"display_name,omitempty"`
	SubjectType string  `json:"subject_type"`
	ExternalKey string  `json:"external_key"`
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
	Success    bool            `json:"success"`
	Message    string          `json:"message,omitempty"`
	SessionID  *uint64         `json:"session_id,string,omitempty"`
	Actor      *ActorInfo      `json:"actor,omitempty"`
	Agents     []AgentInfo     `json:"agents,omitempty"`
	WebhookApp *WebhookAppInfo `json:"webhook_app,omitempty"`
	ApiAuthApp *ApiAuthAppInfo `json:"api_auth_app,omitempty"`
	Session    *model.Session  `json:"session,omitempty"`
}

func (h *Handler) ExchangeTicket(c fiber.Ctx) error {
	ticket := c.Query("ticket")
	if ticket == "" {
		return handler.SendBadRequest(c, nil, "ticket is required")
	}

	redisKey := fmt.Sprintf("session:ticket:%s", ticket)
	ticketJSON, err := database.Redis.Get(c.RequestCtx(), redisKey).Result()
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
	log.Println(deploymentID, deployment.ID)
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
	c fiber.Ctx,
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
	if err := database.Redis.Del(c.RequestCtx(), redisKey).Err(); err != nil {
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
	c fiber.Ctx,
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
		if id < 0 {
			return handler.SendBadRequest(c, nil, fmt.Sprintf("Invalid agent_id: %s", idStr))
		}
		agentIDs[i] = id
	}

	// Determine identifier mode and effective actor scope.
	identifier := model.AgentSessionIdentifierStatic
	if payload.AgentSessionIdentifier != nil {
		identifier = *payload.AgentSessionIdentifier
	}

	var actorID uint64
	switch identifier {
	case model.AgentSessionIdentifierStatic:
		if payload.ActorID == nil || *payload.ActorID == "" {
			return handler.SendBadRequest(c, nil, "actor_id is required for static agent_access tickets")
		}
		parsedActorID, err := strconv.ParseUint(*payload.ActorID, 10, 64)
		if err != nil {
			return handler.SendBadRequest(c, nil, "Invalid actor_id")
		}
		var actor model.Actor
		if err := database.Connection.
			Where("id = ? AND deployment_id = ?", parsedActorID, deployment.ID).
			First(&actor).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return handler.SendBadRequest(c, nil, "actor_id was not found for this deployment")
			}
			return handler.SendInternalServerError(c, err, "Failed to load actor")
		}
		actorID = parsedActorID
	case model.AgentSessionIdentifierSignin:
		if session.ActiveSignin == nil || session.ActiveSignin.UserID == nil {
			return handler.SendUnauthorized(c, nil, "No active sign in for signin agent_access ticket")
		}

		externalKey := strconv.FormatUint(*session.ActiveSignin.UserID, 10)
		var actor model.Actor
		err := database.Connection.
			Where(
				"deployment_id = ? AND subject_type = ? AND external_key = ?",
				deployment.ID,
				agentSessionActorSubjectTypeUser,
				externalKey,
			).
			First(&actor).Error
		if err != nil {
			if err != gorm.ErrRecordNotFound {
				return handler.SendInternalServerError(c, err, "Failed to load actor")
			}

			actor = model.Actor{
				Model:        model.Model{ID: idgen.NextID()},
				DeploymentID: deployment.ID,
				SubjectType:  agentSessionActorSubjectTypeUser,
				ExternalKey:  externalKey,
				Metadata:     json.RawMessage(defaultActorMetadataJSON),
			}
			if err := database.Connection.Create(&actor).Error; err != nil {
				return handler.SendInternalServerError(c, err, "Failed to create actor")
			}
		}

		actorID = actor.ID
	default:
		return handler.SendBadRequest(c, nil, "Invalid agent_session_identifier")
	}

	// Calculate expiration
	var expiresAt *time.Time
	if payload.ExpiresAt > 0 {
		t := time.Unix(payload.ExpiresAt, 0)
		expiresAt = &t
	}

	// Replace any existing agent session for this browser session and deployment.
	if err := database.Connection.
		Where("deployment_id = ? AND session_id = ?", deployment.ID, session.ID).
		Delete(&model.AgentSession{}).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to replace old agent session")
	}

	// Create new AgentSession
	agentSession := model.NewAgentSession(
		session.ID,
		deployment.ID,
		identifier,
		actorID,
		agentIDs,
		expiresAt,
	)

	if err := database.Connection.Create(agentSession).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create agent session")
	}

	response, err := h.getHydratedSessionExchangeResponse(session.ID, deployment.ID)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to fetch agent session")
	}

	// Delete ticket from Redis (single-use enforcement)
	redisKey := fmt.Sprintf("session:ticket:%s", ticket)
	if err := database.Redis.Del(c.RequestCtx(), redisKey).Err(); err != nil {
		fmt.Printf("Warning: Failed to delete ticket after exchange: %v\n", err)
	}

	return handler.SendSuccess(c, ExchangeTicketResponse{
		Success:   true,
		Message:   "Agent session created",
		SessionID: response.SessionID,
		Actor:     response.Actor,
		Agents:    response.Agents,
	})
}

func (h *Handler) getHydratedSessionExchangeResponse(sessionID uint64, deploymentID uint64) (*ExchangeTicketResponse, error) {
	var row hydratedSessionExchangeRow
	if err := database.Connection.Raw(`
		SELECT
			s.id AS session_id,
			json_build_object(
				'id', a.id::text,
				'display_name', a.display_name,
				'subject_type', a.subject_type,
				'external_key', a.external_key
			) AS actor,
			COALESCE((
				SELECT json_agg(
					json_build_object(
						'id', root.id::text,
						'name', root.name,
						'description', root.description,
						'child_agents', COALESCE(children.child_agents, '[]'::json)
					)
					ORDER BY root.name ASC
				)
				FROM ai_agents root
				LEFT JOIN LATERAL (
					SELECT json_agg(
						json_build_object(
							'id', child.id::text,
							'name', child.name,
							'description', child.description
						)
						ORDER BY child.name ASC
					) AS child_agents
					FROM ai_agent_sub_agents rel
					JOIN ai_agents child
						ON child.deployment_id = s.deployment_id
						AND child.id = rel.sub_agent_id
					WHERE rel.deployment_id = s.deployment_id
						AND rel.agent_id = root.id
				) children ON TRUE
				WHERE root.deployment_id = s.deployment_id
					AND root.id = ANY(s.agent_ids)
			), '[]'::json) AS agents
		FROM agent_sessions s
		JOIN actors a
			ON a.id = s.actor_id
			AND a.deployment_id = s.deployment_id
		WHERE s.session_id = ?
			AND s.deployment_id = ?
			AND (s.expires_at IS NULL OR s.expires_at > ?)
		LIMIT 1
	`, sessionID, deploymentID, time.Now()).Scan(&row).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch hydrated agent session: %w", err)
	}
	if row.SessionID == 0 {
		return nil, gorm.ErrRecordNotFound
	}

	response := &ExchangeTicketResponse{
		SessionID: ptr(row.SessionID),
	}
	if len(row.Actor) > 0 && string(row.Actor) != "null" {
		var actor ActorInfo
		if err := json.Unmarshal(row.Actor, &actor); err != nil {
			return nil, fmt.Errorf("failed to parse session actor: %w", err)
		}
		response.Actor = &actor
	}
	if len(row.Agents) > 0 && string(row.Agents) != "null" {
		if err := json.Unmarshal(row.Agents, &response.Agents); err != nil {
			return nil, fmt.Errorf("failed to parse session agents: %w", err)
		}
	}

	return response, nil
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
	var rows []allowlistedAgentRow
	if err := database.Connection.Raw(`
		WITH selected_agents AS (
			SELECT a.id, a.name, a.description
			FROM ai_agents a
			WHERE a.deployment_id = ? AND a.id = ANY(?)
		)
		SELECT
			a.id,
			a.name,
			a.description,
			COALESCE(children.child_agents, '[]'::json) AS child_agents
		FROM selected_agents a
		LEFT JOIN LATERAL (
			SELECT json_agg(
				json_build_object(
					'id', c.id::text,
					'name', c.name,
					'description', COALESCE(c.description, '')
				)
				ORDER BY c.name ASC
			) AS child_agents
			FROM ai_agent_sub_agents rel
			JOIN ai_agents c
				ON c.deployment_id = ?
				AND c.id = rel.sub_agent_id
			WHERE rel.deployment_id = ?
				AND rel.agent_id = a.id
		) children ON TRUE
		ORDER BY a.name ASC
	`, deploymentID, agentIDs, deploymentID, deploymentID).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch agents: %w", err)
	}

	result := make([]AgentInfo, 0, len(rows))
	for _, row := range rows {
		agent := AgentInfo{
			ID:          row.ID,
			Name:        row.Name,
			Description: row.Description,
		}

		if len(row.ChildAgents) > 0 && string(row.ChildAgents) != "null" {
			var children []AgentInfo
			if err := json.Unmarshal(row.ChildAgents, &children); err != nil {
				return nil, fmt.Errorf("failed to parse child agents for agent %d: %w", row.ID, err)
			}
			if len(children) > 0 {
				agent.ChildAgents = children
			}
		}

		result = append(result, agent)
	}

	return result, nil
}

func (h *Handler) getAllowlistedActors(deploymentID uint64, actorIDs []int64) ([]ActorInfo, error) {
	var actors []model.Actor
	if err := database.Connection.
		Where("deployment_id = ? AND id IN ?", deploymentID, actorIDs).
		Find(&actors).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch actors: %w", err)
	}

	var result []ActorInfo
	for _, actor := range actors {
		result = append(result, ActorInfo{
			ID:          actor.ID,
			DisplayName: actor.DisplayName,
			SubjectType: actor.SubjectType,
			ExternalKey: actor.ExternalKey,
		})
	}

	return result, nil
}

func (h *Handler) handleWebhookAppAccessExchange(
	c fiber.Ctx,
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
		return handler.SendInternalServerError(c, err, "Internal server error")
	}

	redisKey := fmt.Sprintf("session:ticket:%s", ticket)
	if err := database.Redis.Del(c.RequestCtx(), redisKey).Err(); err != nil {
		fmt.Printf("Warning: Failed to delete ticket after exchange: %v\n", err)
	}

	return handler.SendSuccess(c, ExchangeTicketResponse{
		Success:    true,
		Message:    "Webhook app session created",
		SessionID:  ptr(webhookAppSession.ID),
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
	c fiber.Ctx,
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
		return handler.SendInternalServerError(c, err, "Internal server error")
	}

	redisKey := fmt.Sprintf("session:ticket:%s", ticket)
	if err := database.Redis.Del(c.RequestCtx(), redisKey).Err(); err != nil {
		fmt.Printf("Warning: Failed to delete ticket after exchange: %v\n", err)
	}

	return handler.SendSuccess(c, ExchangeTicketResponse{
		Success:    true,
		Message:    "API auth app session created",
		SessionID:  ptr(apiAuthAppSession.ID),
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
