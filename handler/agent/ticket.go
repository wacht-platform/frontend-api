package agent

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
)

type TicketPayload struct {
	DeploymentID string   `json:"deployment_id"`
	Identifier   string   `json:"identifier"`
	ContextGroup *string  `json:"context_group"`
	AgentIDs     []string `json:"agent_ids"`
	ExpiresAt    *int64   `json:"expires_at"`
}

type ExchangeTicketResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

func (h *Handler) ExchangeConnectionTicket(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Session required")
	}

	deployment := handler.GetDeployment(c)

	ticket := c.Query("ticket")
	if ticket == "" {
		return handler.SendBadRequest(c, nil, "ticket is required")
	}

	redisKey := fmt.Sprintf("agent:ticket:%s", ticket)
	ticketJSON, err := database.Redis.Get(c.Context(), redisKey).Result()
	if err != nil {
		return handler.SendUnauthorized(c, nil, "Invalid or expired ticket")
	}

	var payload TicketPayload
	if err := json.Unmarshal([]byte(ticketJSON), &payload); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to parse ticket")
	}

	deploymentID, err := strconv.ParseUint(payload.DeploymentID, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, err, "Invalid deployment ID in ticket")
	}

	if deploymentID != deployment.ID {
		return handler.SendUnauthorized(c, nil, "Ticket not valid for this deployment")
	}

	var contextGroup string
	identifier := model.AgentSessionIdentifier(payload.Identifier)

	switch identifier {
	case model.AgentSessionIdentifierSignin:
		if session.ActiveSignin == nil {
			return handler.SendUnauthorized(c, nil, "Active signin required for signin-based agent session")
		}
		contextGroup = strconv.FormatUint(session.ActiveSignin.ID, 10)
	case model.AgentSessionIdentifierStatic:
		if payload.ContextGroup == nil || *payload.ContextGroup == "" {
			return handler.SendBadRequest(c, nil, "context_group required for static identifier")
		}
		contextGroup = *payload.ContextGroup
	default:
		return handler.SendBadRequest(c, nil, "Invalid identifier type")
	}

	var expiresAt *time.Time
	if payload.ExpiresAt != nil {
		t := time.Unix(*payload.ExpiresAt, 0)
		expiresAt = &t
	}

	agentIDs := make([]int64, len(payload.AgentIDs))
	for i, idStr := range payload.AgentIDs {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			return handler.SendBadRequest(c, err, fmt.Sprintf("Invalid agent ID: %s", idStr))
		}
		agentIDs[i] = id
	}

	now := time.Now()
	if err := database.Connection.Model(&model.AgentSession{}).
		Where("session_id = ? AND (expires_at IS NULL OR expires_at > ?)", session.ID, now).
		Update("expires_at", now).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to expire old sessions")
	}

	agentSession := model.NewAgentSession(
		session.ID,
		deployment.ID,
		identifier,
		contextGroup,
		agentIDs,
		expiresAt,
	)

	if err := database.Connection.Create(agentSession).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create agent session")
	}

	return handler.SendSuccess(c, ExchangeTicketResponse{
		Success: true,
		Message: "Agent session created",
	})
}
