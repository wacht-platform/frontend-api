package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/wacht-platform/frontend-api/handler/webhookapp"
)

func setupWebhookAppRoutes(app *fiber.App) {
	h := webhookapp.NewHandler()

	webhookGroup := app.Group("/webhook")

	webhookGroup.Get("/session", h.GetSession)
	webhookGroup.Get("/settings", h.GetSettings)
	webhookGroup.Put("/settings", h.UpdateSettings)
	webhookGroup.Get("/endpoints", h.GetEndpoints)
	webhookGroup.Post("/endpoints", h.CreateEndpoint)
	webhookGroup.Put("/endpoints/:id", h.UpdateEndpoint)
	webhookGroup.Delete("/endpoints/:id", h.DeleteEndpoint)
	webhookGroup.Post("/endpoints/:id/test", h.TestEndpoint)
	webhookGroup.Get("/events", h.GetEvents)
	webhookGroup.Get("/deliveries", h.GetDeliveries)
	webhookGroup.Get("/deliveries/replay", h.ListReplayTasks)
	webhookGroup.Get("/deliveries/replay/:task_id", h.GetReplayTaskStatus)
	webhookGroup.Post("/deliveries/replay/:task_id/cancel", h.CancelReplayTask)
	webhookGroup.Get("/deliveries/:id", h.GetDelivery)
	webhookGroup.Get("/analytics", h.GetAnalytics)
	webhookGroup.Get("/analytics/timeseries", h.GetTimeseries)
	webhookGroup.Get("/stats", h.GetStats)
	webhookGroup.Get("/catalog", h.GetCatalog)
	webhookGroup.Post("/rotate-secret", h.RotateSecret)
	webhookGroup.Post("/deliveries/replay", h.ReplayDelivery)
}
