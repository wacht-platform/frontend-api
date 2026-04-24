package router

import (
	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/handler/external_connection"
)

func setupExternalConnectionRoutes(app *fiber.App) {
	h := external_connection.NewHandler()

	group := app.Group("/ai/external-connections")
	group.Get("/", h.List)
	group.Post("/:provider/:slug/connect", h.Connect)
	group.Delete("/:provider/:slug", h.Disconnect)
}
