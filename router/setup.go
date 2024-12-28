package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/auth"
	"github.com/ilabs/wacht-fe/middleware"
)

func SetupAppRoutes(app *fiber.App) {
	app.Use(middleware.SetDeploymentMiddleware)
	auth := app.Group("/auth")

	setupAuthRoutes(auth)
}

func setupAuthRoutes(router fiber.Router) {
	router.Post("/sign-in", auth.SignIn)
	router.Post("/sign-up", auth.SignUp)
	router.Get("/methods", auth.AuthMethods)
	router.Post("/sso", auth.InitSSO)
	router.Get("/sso-callback", auth.SSOCallback)
	// router.Post("/check-username", auth.)
}
