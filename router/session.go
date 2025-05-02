package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/session"
)

func setupSessionRoutes(app *fiber.App) {
	sessionHandler := session.NewHandler()
	router := app.Group("/session")

	router.Get("/", sessionHandler.GetCurrentSession)
	router.Post("/switch-sign-in", sessionHandler.SwitchActiveSignIn)
	router.Post("/sign-out", sessionHandler.SignOut)
	router.Put("/switch-organization", sessionHandler.SwitchOrganization)
	router.Put("/switch-workspace", sessionHandler.SwitchWorkspace)
}
