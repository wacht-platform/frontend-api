package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/wacht-platform/frontend-api/handler/apiauthapp"
)

func setupApiAuthAppRoutes(app *fiber.App) {
	h := apiauthapp.NewHandler()

	apiAuthGroup := app.Group("/api-auth")

	apiAuthGroup.Get("/session", h.GetSession)
	apiAuthGroup.Get("/keys", h.GetKeys)
	apiAuthGroup.Post("/keys", h.CreateKey)
	apiAuthGroup.Post("/keys/:id/rotate", h.RotateKey)
	apiAuthGroup.Post("/keys/:id/revoke", h.RevokeKey)
	apiAuthGroup.Get("/audit/logs", h.GetAuditLogs)
	apiAuthGroup.Get("/audit/analytics", h.GetAuditAnalytics)
	apiAuthGroup.Get("/audit/timeseries", h.GetAuditTimeseries)
}
