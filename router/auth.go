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
	router.Post("/sso", authHandler.InitSSO)
	router.Get("/sso-callback", authHandler.SSOCallback)
	router.Get("/identifier-availability", authHandler.CheckIdentifierAvailability)
	router.Get("/prepare-authentication", authHandler.SetupAuthenticator)
	router.Post("/prepare-verification", authHandler.PrepareVerification)
	router.Post("/verify-otp", authHandler.VerifyOTP)
	router.Post("/prepare-reset-password", authHandler.PreparePasswordReset)
	router.Post("/reset-password", authHandler.ResetPassword)
}
