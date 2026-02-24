package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/oauth_consent"
)

func setupOAuthConsentRoutes(app *fiber.App) {
	h := oauth_consent.NewHandler()
	group := app.Group("/oauth/consent")

	group.Get("/init", h.Init)
	group.Get("/details", h.Details)
	group.Post("/submit", h.Submit)
}
