package agent

import (
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler"
)

type Handler struct {
	service *Service
}

func NewHandler() *Handler {
	return &Handler{
		service: NewService(),
	}
}

// verifyAgentSession authenticates via session cookie and AgentSession
func (h *Handler) verifyAgentSession(c *fiber.Ctx) (string, *string, error) {
	session := handler.GetSession(c)
	if session == nil {
		return "", nil, fiber.NewError(fiber.StatusUnauthorized, "Session required")
	}

	deployment := handler.GetDeployment(c)

	agentSession, err := h.service.GetActiveAgentSession(session.ID, deployment.ID)
	if err != nil {
		return "", nil, fiber.NewError(fiber.StatusUnauthorized, "No active agent session")
	}

	// For now, use "default" as agent name since AgentSession stores agent_ids not names
	agentName := "default"

	return agentName, &agentSession.ContextGroup, nil
}

func (h *Handler) ListContexts(c *fiber.Ctx) error {
	_, contextGroup, err := h.verifyAgentSession(c)
	if err != nil {
		return err
	}

	deployment := handler.GetDeployment(c)

	params := ListContextsRequest{
		Limit:  c.QueryInt("limit", 10),
		Offset: c.QueryInt("offset", 0),
		Status: c.Query("status"),
		Search: c.Query("search"),
	}

	response, err := h.service.ListContexts(deployment.ID, contextGroup, params)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, response)
}

func (h *Handler) CreateContext(c *fiber.Ctx) error {
	_, contextGroup, err := h.verifyAgentSession(c)
	if err != nil {
		return err
	}

	title := c.FormValue("title")
	if title == "" {
		return handler.SendBadRequest(c, nil, "Title is required")
	}

	var systemInstructions *string
	if si := c.FormValue("system_instructions"); si != "" {
		systemInstructions = &si
	}

	req := CreateContextRequest{
		Title:              title,
		SystemInstructions: systemInstructions,
	}

	deployment := handler.GetDeployment(c)

	context, err := h.service.CreateContext(deployment.ID, contextGroup, req)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, context)
}

func (h *Handler) GetContext(c *fiber.Ctx) error {
	_, contextGroup, err := h.verifyAgentSession(c)
	if err != nil {
		return err
	}

	contextIDStr := c.Params("id")
	contextID, err := strconv.ParseUint(contextIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	deployment := handler.GetDeployment(c)

	context, err := h.service.GetContext(deployment.ID, contextGroup, contextID)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, context)
}

func (h *Handler) DeleteContext(c *fiber.Ctx) error {
	_, contextGroup, err := h.verifyAgentSession(c)
	if err != nil {
		return err
	}

	contextIDStr := c.Params("id")
	contextID, err := strconv.ParseUint(contextIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	deployment := handler.GetDeployment(c)

	if err := h.service.DeleteContext(deployment.ID, contextGroup, contextID); err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *Handler) GetContextMessages(c *fiber.Ctx) error {
	_, contextGroup, err := h.verifyAgentSession(c)
	if err != nil {
		return err
	}

	contextIDStr := c.Params("id")
	contextID, err := strconv.ParseUint(contextIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	limit := c.QueryInt("limit", 50)
	if limit > 100 {
		limit = 100
	}

	beforeID := c.Query("before_id")
	afterID := c.Query("after_id")

	deployment := handler.GetDeployment(c)

	messages, hasMore, err := h.service.GetContextMessages(
		deployment.ID,
		contextGroup,
		contextID,
		limit,
		beforeID,
		afterID,
	)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, ListMessagesResponse{
		Data:    messages,
		HasMore: hasMore,
	})
}

// GetActiveIntegrations returns integrations active for the current context_group
func (h *Handler) GetActiveIntegrations(c *fiber.Ctx) error {
	agentName, contextGroup, err := h.verifyAgentSession(c)
	if err != nil {
		return err
	}

	if contextGroup == nil || *contextGroup == "" {
		return handler.SendBadRequest(c, nil, "Context group required in token")
	}

	deployment := handler.GetDeployment(c)

	integrations, err := h.service.GetActiveIntegrations(deployment.ID, agentName, *contextGroup)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, integrations)
}

func (h *Handler) RemoveIntegration(c *fiber.Ctx) error {
	_, contextGroup, err := h.verifyAgentSession(c)
	if err != nil {
		return err
	}

	if contextGroup == nil || *contextGroup == "" {
		return handler.SendBadRequest(c, nil, "Context group required in token")
	}

	integrationIDStr := c.Params("integration_id")
	integrationID, err := strconv.ParseUint(integrationIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid integration ID")
	}

	deployment := handler.GetDeployment(c)

	if err := h.service.RemoveIntegration(deployment.ID, *contextGroup, integrationID); err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// ListAvailableIntegrations lists all integrations available for the agent
func (h *Handler) ListAvailableIntegrations(c *fiber.Ctx) error {
	agentName, contextGroup, err := h.verifyAgentSession(c)
	if err != nil {
		return err
	}

	deployment := handler.GetDeployment(c)

	integrations, err := h.service.ListAvailableIntegrations(deployment.ID, agentName, contextGroup)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, integrations)
}

func (h *Handler) GenerateConsentURL(c *fiber.Ctx) error {
	_, contextGroup, err := h.verifyAgentSession(c)
	if err != nil {
		return err
	}

	if contextGroup == nil || *contextGroup == "" {
		return handler.SendBadRequest(c, nil, "Context group required in token")
	}

	integrationIDStr := c.Params("integration_id")
	integrationID, err := strconv.ParseUint(integrationIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid integration ID")
	}

	redirectURL := c.Query("redirect_url", "")

	deployment := handler.GetDeployment(c)

	consentURL, state, err := h.service.GenerateConsentURL(deployment.ID, *contextGroup, integrationID, redirectURL)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, map[string]interface{}{
		"consent_url": consentURL,
		"state":       state,
		"expires_in":  900,
	})
}
