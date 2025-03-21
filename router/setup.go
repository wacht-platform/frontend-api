package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/ilabs/wacht-fe/middleware"
)

func Setup(app *fiber.App) {
	setupMiddleware(app)
	setupRoutes(app)
}

func setupRoutes(app *fiber.App) {
	setupAuthRoutes(app)
	setupDeploymentRoutes(app)
	setupSessionRoutes(app)
	setupOrganizationRoutes(app)
	setupWorkspaceRoutes(app)
	setupUserRoutes(app)
}

func setupMiddleware(app *fiber.App) {
	app.Use(recover.New())
	app.Use(cors.New(corsSettings()))
	app.Use(middleware.SetDeploymentMiddleware)
	app.Use(middleware.SetSessionMiddleware)
	// app.Use(middleware.RateLimiter)
}

func corsSettings() cors.Config {
	corsSetting := cors.ConfigDefault

	// if os.Getenv("MODE") == "staging" {
	corsSetting.AllowHeaders = "X-Development-Session"
	corsSetting.ExposeHeaders = "X-Development-Session"
	// }

	return corsSetting
}
