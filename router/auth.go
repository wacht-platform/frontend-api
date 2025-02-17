package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/auth"
)

func setupAuthRoutes(app *fiber.App) {
	authHandler := auth.NewHandler()
	router := app.Group("/auth")

	router.Post("/signin", authHandler.SignIn)
	router.Post("/signup", authHandler.SignUp)
	router.Post("/oauth2/init", authHandler.InitSSO)
	router.Get("/oauth2/callback", authHandler.SSOCallback)
	router.Get(
		"/identifier-availability",
		authHandler.CheckIdentifierAvailability,
	)

	router.Post(
		"/prepare-verification",
		authHandler.PrepareVerification,
	)
	router.Post(
		"/attempt-verification",
		authHandler.AttemptVerification,
	)

}
