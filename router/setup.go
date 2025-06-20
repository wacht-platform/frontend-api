package router

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/ilabs/wacht-fe/middleware"
	"github.com/ilabs/wacht-fe/model"
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
	deployment, ok := c.Locals("deployment").(model.Deployment)
	fmt.Println(deployment, ok)
	if !ok {
		return cors.Config{
			AllowOrigins:     "",
			AllowCredentials: true,
			AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		}
	}

	host := fmt.Sprintf("https://%s", deployment.FrontendHost)

	if deployment.Mode == model.DeploymentModeStaging {
		return cors.Config{
			AllowHeaders:     "X-Development-Session,Content-Type",
			AllowCredentials: true,
			AllowOriginsFunc: func(origin string) bool { return true },
			AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		}
	}

	return cors.Config{
		AllowHeaders:     "Content-Type,X-Development-Session",
		AllowOrigins:     host,
		AllowCredentials: true,
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
	}
}
