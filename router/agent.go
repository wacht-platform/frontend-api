package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/agent"
)

func setupAgentRoutes(app *fiber.App) {
	h := agent.NewHandler()

	agentGroup := app.Group("/api/agent")

	agentGroup.Get("/contexts", h.ListContexts)
	agentGroup.Get("/session", h.GetSession)
	agentGroup.Post("/contexts", h.CreateContext)
	agentGroup.Get("/contexts/:id", h.GetContext)
	agentGroup.Post("/contexts/:id/update", h.UpdateContext)
	agentGroup.Post("/contexts/:id/delete", h.DeleteContext)
	agentGroup.Get("/contexts/:id/messages", h.GetContextMessages)
	agentGroup.Get("/contexts/:context_id/files/:filename", h.ServeFile)
	agentGroup.Get("/integrations", h.GetActiveIntegrations)
	agentGroup.Post("/integrations/:integration_id/remove", h.RemoveIntegration)
	agentGroup.Post("/integrations/:integration_id/consent-url", h.GenerateConsentURL)
	agentGroup.Post("/ticket/exchange", h.ExchangeConnectionTicket)
	agentGroup.Post("/contexts/:id/execute", h.ExecuteAgent)
}
