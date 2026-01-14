package agent

import (
	"context"
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
)

type GenerateTicketRequest struct {
	AgentIDs     []int64 `json:"agent_ids"`
	ContextGroup string  `json:"context_group"`
	ExpiresIn    *int    `json:"expires_in"`
}

type GenerateTicketResponse struct {
	Ticket    string `json:"ticket"`
	ExpiresAt int64  `json:"expires_at"`
}

func (h *Handler) GenerateTicket(c *fiber.Ctx) error {
	deployment := handler.GetDeployment(c)

	var req GenerateTicketRequest
	if err := c.BodyParser(&req); err != nil {
		return handler.SendBadRequest(c, nil, "Invalid request body")
	}

	if len(req.AgentIDs) == 0 {
		return handler.SendBadRequest(c, nil, "agent_ids is required")
	}

	if req.ContextGroup == "" {
		return handler.SendBadRequest(c, nil, "context_group is required")
	}

	ttl := 5 * time.Minute
	if req.ExpiresIn != nil && *req.ExpiresIn > 0 {
		ttl = time.Duration(*req.ExpiresIn) * time.Second
	}

	ticket := uuid.New().String()
	expiresAt := time.Now().Add(ttl).Unix()

	payload := TicketPayload{
		DeploymentID: deployment.ID,
		Identifier:   "static",
		ContextGroup: &req.ContextGroup,
		AgentIDs:     req.AgentIDs,
		ExpiresAt:    &expiresAt,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to serialize ticket")
	}

	redisKey := "agent:ticket:" + ticket
	if err := database.Redis.Set(context.Background(), redisKey, payloadJSON, ttl).Err(); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to store ticket")
	}

	return handler.SendSuccess(c, GenerateTicketResponse{
		Ticket:    ticket,
		ExpiresAt: expiresAt,
	})
}
