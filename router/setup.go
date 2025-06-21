package router

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/ilabs/wacht-fe/handler"
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
	setupWaitlistRoutes(app)
}

func setupMiddleware(app *fiber.App) {
	app.Use(recover.New())
	app.Use(middleware.SetDeploymentMiddleware)
	app.Use(func(c *fiber.Ctx) error {
		cfg := corsSettings(c)
		return cors.New(cfg)(c)
	})
	app.Use(middleware.SetSessionMiddleware)
}

func corsSettings(c *fiber.Ctx) cors.Config {
	path := c.Path()

	if strings.HasPrefix(path, "/.well") {
		return cors.Config{
			AllowHeaders: "X-Development-Session",
			AllowOrigins: "*",
			AllowMethods: "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		}
	}

	deployment := handler.GetDeployment(c)

	if !deployment.IsProduction() {
		return cors.Config{
			AllowHeaders: "X-Development-Session",
			AllowOrigins: "*",
			AllowMethods: "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		}
	}

	return cors.Config{
		AllowOriginsFunc: func(origin string) bool {
			return deployment.FrontendHost == strings.TrimPrefix(origin, "https://")
		},
		AllowCredentials: true,
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
	}
}
