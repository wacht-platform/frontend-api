package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/auth"
)

func setupAuthRoutes(
	app *fiber.App,
) {
	authHandler := auth.NewHandler()
	router := app.Group("/auth")

	router.Post("/signin", authHandler.SignIn)
	router.Post("/signup", authHandler.SignUp)
	router.Post("/oauth2/init", authHandler.InitOAuth2)
	router.Get("/oauth2/callback", authHandler.OAuth2Callback)
	router.Post("/complete-profile", authHandler.CompleteProfile)
	router.Get("/identifier-availability", authHandler.CheckIdentifierAvailability)
	router.Post("/prepare-verification", authHandler.PrepareVerification)
	router.Post("/attempt-verification", authHandler.AttemptVerification)
	router.Get("/verify-magic-link", authHandler.VerifyMagicLink)
	router.Post("/forgot-password", authHandler.ForgotPassword)
	router.Post("/reset-password", authHandler.ResetPassword)
	router.Post("/identify", authHandler.Identify)
	router.Get("/sso/metadata", authHandler.SSOMetadata)
	router.Post("/sso/login", authHandler.SSOLogin)
	router.Post("/sso/callback", authHandler.EnterpriseSSOCallback)
	router.Get("/sso/oidc/callback", authHandler.OIDCCallback)
}
