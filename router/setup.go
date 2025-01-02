package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/ilabs/wacht-fe/handler/auth"
	"github.com/ilabs/wacht-fe/middleware"
)

func SetupAppRoutes(app *fiber.App) {
	app.Use(middleware.SetDeploymentMiddleware)
	app.Use(recover.New())
	app.Use(cors.New(cors.ConfigDefault))
	auth := app.Group("/auth")

	setupAuthRoutes(auth)
}

func setupAuthRoutes(router fiber.Router) {
	router.Post("/signin", auth.SignIn)
	router.Post("/signup", auth.SignUp)
	router.Get("/methods", auth.AuthMethods)
	router.Post("/sso", auth.InitSSO)
	router.Get("/sso-callback", auth.SSOCallback)
	router.Post("/send-otp", auth.SendOTP)
	// router.Post("/check-username", auth.)
}
