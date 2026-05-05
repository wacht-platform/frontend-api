package router

import (
	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/handler/session"
	"github.com/wacht-platform/frontend-api/middleware"
	"github.com/wacht-platform/frontend-api/service"
)

func setupSessionRoutes(app *fiber.App) {
	sessionHandler := session.NewHandler()
	router := app.Group("/session")
	tokenRateLimiters := middleware.SessionTokenRateLimiters(service.GetNATS())

	router.Get("/", sessionHandler.GetCurrentSession)
	router.Get(
		"/token",
		tokenRateLimiters[0],
		tokenRateLimiters[1],
		tokenRateLimiters[2],
		sessionHandler.GetToken,
	)
	router.Post("/switch-sign-in", sessionHandler.SwitchActiveSignIn)
	router.Post("/sign-out", sessionHandler.SignOut)
	router.Post("/switch-organization", sessionHandler.SwitchOrganization)
	router.Post("/switch-workspace", sessionHandler.SwitchWorkspace)
	router.Get("/ticket/exchange", sessionHandler.ExchangeTicket)
}
