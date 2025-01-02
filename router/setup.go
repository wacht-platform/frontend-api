package router

import (
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/ilabs/wacht-fe/handler/auth"
	"github.com/ilabs/wacht-fe/handler/deployment"
	"github.com/ilabs/wacht-fe/handler/session"
	"github.com/ilabs/wacht-fe/middleware"
)

func Setup(app *fiber.App) {
	setupMiddleware(app)
	setupRoutes(app)
}

func setupRoutes(app *fiber.App) {
	auth := app.Group("/auth")
	setupAuthRoutes(auth)

	deployment := app.Group("/deployment")
	setupDeploymentRoutes(deployment)

	sessions := app.Group("/sessions")
	setupSessionRoutes(sessions)
}

func setupMiddleware(app *fiber.App) {
	// app.Use(recover.New())
	app.Use(cors.New(corsSettings()))
	app.Use(middleware.SetDeploymentMiddleware)
	app.Use(middleware.SetSessionMiddleware)
}

func corsSettings() cors.Config {
	corsSetting := cors.ConfigDefault
	// corsSetting.AllowCredentials = os.Getenv("MODE") == "development"

	if os.Getenv("MODE") == "staging" {
		corsSetting.AllowHeaders = "X-Development-Session"
		corsSetting.ExposeHeaders = "X-Development-Session"
	}

	return corsSetting
}

func setupAuthRoutes(router fiber.Router) {
	authHandler := auth.NewHandler()

	router.Post("/signin", authHandler.SignIn)
	router.Post("/signup", authHandler.SignUp)
	router.Get("/methods", authHandler.AuthMethods)
	router.Post("/sso", authHandler.InitSSO)
	router.Get("/sso-callback", authHandler.SSOCallback)
}

func setupDeploymentRoutes(router fiber.Router) {
	router.Get("/", deployment.GetDeployment)
}

func setupSessionRoutes(router fiber.Router) {
	sessionHandler := session.NewHandler()

	router.Get("/current", sessionHandler.GetCurrentSession)
	router.Delete("/", sessionHandler.DeleteSession)
	router.Post("/switch", sessionHandler.SwitchActiveSignIn)
}
