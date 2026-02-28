package agent

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
)

type Handler struct {
	service *Service
}

func NewHandler() *Handler {
	return &Handler{
		service: NewService(),
	}
}

func (h *Handler) verifyAgentSession(c *fiber.Ctx) (*string, error) {
	agentSession, err := h.getAgentSession(c)
	if err != nil {
		return nil, fiber.NewError(fiber.StatusUnauthorized, "No active agent session")
	}

	contextGroup, err := h.resolveAgentSessionContextGroup(c, agentSession)
	if err != nil {
		return nil, err
	}

	return &contextGroup, nil
}

func (h *Handler) resolveAuthorizedAgentName(
	c *fiber.Ctx,
	deploymentID uint64,
	agentSession *model.AgentSession,
	rawAgentName string,
) (string, error) {
	agentName := strings.TrimSpace(rawAgentName)
	if agentName == "" {
		return "", handler.SendBadRequest(c, nil, "agent_name query parameter required")
	}

	allowlistedAgents, err := h.service.GetAllowlistedAgents(deploymentID, agentSession.AgentIDs)
	if err != nil {
		return "", handler.SendInternalServerError(c, nil, err.Error())
	}

	matches := make([]string, 0, 1)
	for _, agent := range allowlistedAgents {
		if strings.EqualFold(agent.Name, agentName) {
			matches = append(matches, agent.Name)
		}
	}

	if len(matches) == 0 {
		return "", handler.SendBadRequest(c, nil, "agent_name is not allowlisted for this session")
	}
	if len(matches) > 1 {
		return "", handler.SendBadRequest(c, nil, "agent_name is ambiguous; use a unique agent name")
	}

	return matches[0], nil
}

func (h *Handler) ListContexts(c *fiber.Ctx) error {
	contextGroup, err := h.verifyAgentSession(c)
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
	contextGroup, err := h.verifyAgentSession(c)
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

	deployment := handler.GetDeployment(c)

	context, err := h.service.CreateContext(deployment.ID, contextGroup, title, systemInstructions)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, context)
}

func (h *Handler) GetContext(c *fiber.Ctx) error {
	contextGroup, err := h.verifyAgentSession(c)
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
	contextGroup, err := h.verifyAgentSession(c)
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

func (h *Handler) UpdateContext(c *fiber.Ctx) error {
	contextGroup, err := h.verifyAgentSession(c)
	if err != nil {
		return err
	}

	contextIDStr := c.Params("id")
	contextID, err := strconv.ParseUint(contextIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	title := c.FormValue("title")

	deployment := handler.GetDeployment(c)

	if err := h.service.UpdateContext(deployment.ID, contextGroup, contextID, title); err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, map[string]string{})
}

func (h *Handler) GetContextMessages(c *fiber.Ctx) error {
	contextGroup, err := h.verifyAgentSession(c)
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

func (h *Handler) GetActiveIntegrations(c *fiber.Ctx) error {
	agentSession, err := h.getAgentSession(c)
	if err != nil {
		return err
	}

	contextGroup, err := h.resolveAgentSessionContextGroup(c, agentSession)
	if err != nil {
		return err
	}
	if contextGroup == "" {
		return handler.SendBadRequest(c, nil, "Context group required in token")
	}

	deployment := handler.GetDeployment(c)
	agentName, err := h.resolveAuthorizedAgentName(c, deployment.ID, agentSession, c.Query("agent_name"))
	if err != nil {
		return err
	}

	integrations, err := h.service.GetActiveIntegrations(deployment.ID, agentName, contextGroup)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, integrations)
}

func (h *Handler) RemoveIntegration(c *fiber.Ctx) error {
	contextGroup, err := h.verifyAgentSession(c)
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

func (h *Handler) GenerateConsentURL(c *fiber.Ctx) error {
	contextGroup, err := h.verifyAgentSession(c)
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

func (h *Handler) ListMcpServers(c *fiber.Ctx) error {
	agentSession, err := h.getAgentSession(c)
	if err != nil {
		return err
	}

	contextGroup, err := h.resolveAgentSessionContextGroup(c, agentSession)
	if err != nil {
		return err
	}
	if contextGroup == "" {
		return handler.SendBadRequest(c, nil, "Context group required in token")
	}

	deployment := handler.GetDeployment(c)
	agentName, err := h.resolveAuthorizedAgentName(c, deployment.ID, agentSession, c.Query("agent_name"))
	if err != nil {
		return err
	}

	servers, err := h.service.GetActiveMcpServers(deployment.ID, agentName, contextGroup)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, servers)
}

func (h *Handler) ConnectMcpServer(c *fiber.Ctx) error {
	agentSession, err := h.getAgentSession(c)
	if err != nil {
		return err
	}

	contextGroup, err := h.resolveAgentSessionContextGroup(c, agentSession)
	if err != nil {
		return err
	}
	if contextGroup == "" {
		return handler.SendBadRequest(c, nil, "Context group required in token")
	}

	mcpServerIDStr := c.Params("mcp_server_id")
	mcpServerID, err := strconv.ParseUint(mcpServerIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid MCP server ID")
	}

	deployment := handler.GetDeployment(c)
	agentName, err := h.resolveAuthorizedAgentName(c, deployment.ID, agentSession, c.Query("agent_name"))
	if err != nil {
		return err
	}
	session := handler.GetSession(c)
	if session == nil {
		return fiber.NewError(fiber.StatusUnauthorized, "Session required")
	}
	callbackURL := "https://agentlink.wacht.services/service/mcp/consent/callback"

	connectResult, err := h.service.ConnectMcpServer(
		deployment.ID,
		session.ID,
		agentName,
		contextGroup,
		mcpServerID,
		callbackURL,
		"",
	)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, map[string]any{
		"requires_oauth": connectResult.RequiresOAuth,
		"oauth_url":      connectResult.OAuthURL,
	})
}

func (h *Handler) DisconnectMcpServer(c *fiber.Ctx) error {
	agentSession, err := h.getAgentSession(c)
	if err != nil {
		return err
	}

	contextGroup, err := h.resolveAgentSessionContextGroup(c, agentSession)
	if err != nil {
		return err
	}
	if contextGroup == "" {
		return handler.SendBadRequest(c, nil, "Context group required in token")
	}

	mcpServerIDStr := c.Params("mcp_server_id")
	mcpServerID, err := strconv.ParseUint(mcpServerIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid MCP server ID")
	}

	deployment := handler.GetDeployment(c)
	agentName, err := h.resolveAuthorizedAgentName(c, deployment.ID, agentSession, c.Query("agent_name"))
	if err != nil {
		return err
	}

	if err := h.service.DisconnectMcpServer(deployment.ID, agentName, contextGroup, mcpServerID); err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, map[string]string{})
}

func (h *Handler) getAgentSession(c *fiber.Ctx) (*model.AgentSession, error) {
	session := handler.GetSession(c)
	if session == nil {
		return nil, fiber.NewError(fiber.StatusUnauthorized, "Session required")
	}
	deployment := handler.GetDeployment(c)
	return h.service.GetActiveAgentSession(session.ID, deployment.ID)
}

func (h *Handler) resolveAgentSessionContextGroup(
	c *fiber.Ctx,
	agentSession *model.AgentSession,
) (string, error) {
	session := handler.GetSession(c)
	if session == nil {
		return "", fiber.NewError(fiber.StatusUnauthorized, "Session required")
	}

	switch agentSession.Identifier {
	case model.AgentSessionIdentifierSignin:
		if session.ActiveSignin == nil || session.ActiveSignin.UserID == nil {
			return "", fiber.NewError(
				fiber.StatusUnauthorized,
				"No active sign in for signin-scoped agent session",
			)
		}
		return strconv.FormatUint(*session.ActiveSignin.UserID, 10), nil
	case model.AgentSessionIdentifierStatic:
		return strings.TrimSpace(agentSession.ContextGroup), nil
	default:
		return "", fiber.NewError(
			fiber.StatusUnauthorized,
			fmt.Sprintf("Unsupported agent session identifier: %s", agentSession.Identifier),
		)
	}
}

func (h *Handler) GetSession(c *fiber.Ctx) error {
	agentSession, err := h.getAgentSession(c)
	if err != nil {
		return fiber.NewError(fiber.StatusUnauthorized, "No active agent session")
	}

	contextGroup, err := h.resolveAgentSessionContextGroup(c, agentSession)
	if err != nil {
		return err
	}

	deployment := handler.GetDeployment(c)

	agents, err := h.service.GetAllowlistedAgents(deployment.ID, agentSession.AgentIDs)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, AgentSessionResponse{
		SessionID:    strconv.FormatUint(agentSession.ID, 10),
		ContextGroup: contextGroup,
		Agents:       agents,
	})
}
