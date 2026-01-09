package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/agent"
)

func setupAgentRoutes(app *fiber.App) {
	h := agent.NewHandler()

	agentGroup := app.Group("/api/agent")

	agentGroup.Get("/contexts", h.ListContexts)
	agentGroup.Post("/contexts", h.CreateContext)
	agentGroup.Get("/contexts/:id", h.GetContext)
	agentGroup.Post("/contexts/:id/delete", h.DeleteContext)
	agentGroup.Get("/contexts/:id/messages", h.GetContextMessages)
	agentGroup.Get("/contexts/:context_id/files/:filename", h.ServeFile)

	// Integration management routes (use context_group from JWT)
	agentGroup.Get("/integrations", h.GetActiveIntegrations)
	agentGroup.Post("/integrations/:integration_id", h.AddIntegration)
	agentGroup.Delete("/integrations/:integration_id", h.RemoveIntegration)
	agentGroup.Get("/available-integrations", h.ListAvailableIntegrations)
}
