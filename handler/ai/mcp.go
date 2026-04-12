package ai

import (
	"strconv"

	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/handler"
)

func (h *Handler) ListActorMcpServers(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}

	deployment := handler.GetDeployment(c)
	servers, err := h.service.ListActorMcpServers(deployment.ID, actorID)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to load MCP servers")
	}
	return handler.SendSuccess(c, servers)
}

func (h *Handler) ConnectActorMcpServer(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	mcpServerID, err := strconv.ParseUint(c.Params("mcp_server_id"), 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid mcp_server_id")
	}

	deployment := handler.GetDeployment(c)
	authURL, err := h.service.BuildActorMcpServerConnectURL(deployment, actorID, mcpServerID)
	if err != nil {
		return handler.SendBadRequest(c, err, err.Error())
	}
	return handler.SendSuccess(c, ActorMcpServerConnectResponse{AuthURL: authURL})
}

func (h *Handler) DisconnectActorMcpServer(c fiber.Ctx) error {
	actorID, _, err := h.getActorScope(c)
	if err != nil {
		return err
	}
	mcpServerID, err := strconv.ParseUint(c.Params("mcp_server_id"), 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid mcp_server_id")
	}

	deployment := handler.GetDeployment(c)
	if err := h.service.DisconnectActorMcpServer(deployment.ID, actorID, mcpServerID); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to disconnect MCP server")
	}
	return handler.SendSuccess(c, fiber.Map{"success": true})
}
