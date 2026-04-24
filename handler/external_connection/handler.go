package external_connection

import (
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/handler"
)

type Handler struct {
	service *Service
}

func NewHandler() *Handler { return &Handler{service: NewService()} }

func (h *Handler) requireActor(c fiber.Ctx) (uint64, uint64, error) {
	session := handler.GetSession(c)
	if session == nil {
		return 0, 0, fiber.NewError(fiber.StatusUnauthorized, "Session required")
	}
	deployment := handler.GetDeployment(c)
	agentSession, err := h.service.GetActiveAgentSession(session.ID, deployment.ID)
	if err != nil {
		return 0, 0, fiber.NewError(fiber.StatusUnauthorized, "No active agent session")
	}
	return deployment.ID, agentSession.ActorID, nil
}

func (h *Handler) List(c fiber.Ctx) error {
	deploymentID, actorID, err := h.requireActor(c)
	if err != nil {
		return err
	}
	connections, err := h.service.List(deploymentID, actorID)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to load connections")
	}
	return handler.SendSuccess(c, connections)
}

type connectRequest struct {
	ReturnURL string `json:"return_url"`
}

func (h *Handler) Connect(c fiber.Ctx) error {
	deploymentID, actorID, err := h.requireActor(c)
	if err != nil {
		return err
	}

	provider := strings.ToLower(c.Params("provider"))
	slug := strings.ToLower(c.Params("slug"))

	var body connectRequest
	_ = c.Bind().Body(&body)

	callbackURL := buildCallbackURL(c, provider)
	redirectURL, err := h.service.Connect(deploymentID, actorID, provider, slug, callbackURL, strings.TrimSpace(body.ReturnURL))
	if err != nil {
		return handler.SendBadRequest(c, err, err.Error())
	}
	return handler.SendSuccess(c, fiber.Map{"redirect_url": redirectURL})
}

func (h *Handler) Disconnect(c fiber.Ctx) error {
	deploymentID, actorID, err := h.requireActor(c)
	if err != nil {
		return err
	}
	provider := strings.ToLower(c.Params("provider"))
	slug := strings.ToLower(c.Params("slug"))
	if err := h.service.Disconnect(deploymentID, actorID, provider, slug); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to disconnect")
	}
	return handler.SendSuccess(c, fiber.Map{"success": true})
}

// buildCallbackURL points at agentlink — the shared callback host used across
// the platform for third-party OAuth redirects (same pattern as MCP consent).
func buildCallbackURL(_ fiber.Ctx, provider string) string {
	return "https://agentlink.wacht.services/service/external/" + provider + "/callback"
}
