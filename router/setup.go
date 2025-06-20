package router

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/ilabs/wacht-fe/middleware"
	"github.com/ilabs/wacht-fe/utils"
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
	app.Use(func(c *fiber.Ctx) error {
		cfg := corsSettings(c)
		return cors.New(cfg)(c)
	})
	app.Use(middleware.SetDeploymentMiddleware)
	app.Use(middleware.SetSessionMiddleware)
}

func corsSettings(c *fiber.Ctx) cors.Config {
	host := c.Hostname()

	if strings.HasSuffix(host, "backend-api.services") {
		return cors.Config{
			AllowHeaders:     "X-Development-Session,Content-Type",
			AllowCredentials: true,
			AllowOriginsFunc: func(origin string) bool { return true },
			AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		}
	}

	return cors.Config{
		AllowHeaders: "Content-Type,X-Development-Session",
		AllowOriginsFunc: func(origin string) bool {
			deployment, err := utils.GetDeploymentByHost(host)
			if err == nil && deployment != nil {
				return deployment.FrontendHost == strings.TrimPrefix(origin, "https://")
			}
			return false
		},
		AllowCredentials: true,
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
	}
}
