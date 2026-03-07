package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/wacht-platform/frontend-api/handler/session"
)

func setupSessionRoutes(app *fiber.App) {
	sessionHandler := session.NewHandler()
	router := app.Group("/session")

	router.Get("/", sessionHandler.GetCurrentSession)
	router.Get("/token", sessionHandler.GetToken)
	router.Post("/switch-sign-in", sessionHandler.SwitchActiveSignIn)
	router.Post("/sign-out", sessionHandler.SignOut)
	router.Post("/switch-organization", sessionHandler.SwitchOrganization)
	router.Post("/switch-workspace", sessionHandler.SwitchWorkspace)
	router.Get("/ticket/exchange", sessionHandler.ExchangeTicket)
}
