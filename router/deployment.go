package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/deployment"
)

func setupDeploymentRoutes(app *fiber.App) {
	router := app.Group("/deployment")
	router.Get("/", deployment.GetDeployment)
}
