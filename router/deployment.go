package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/wacht-platform/frontend-api/handler/deployment"
)

func setupDeploymentRoutes(app *fiber.App) {
	router := app.Group("/deployment")
	router.Get("/", deployment.GetDeployment)
	router.Get("/invitations/validate", deployment.ValidateInvitation)
}
