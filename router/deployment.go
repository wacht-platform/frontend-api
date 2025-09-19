package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/deployment"
)

func setupDeploymentRoutes(app *fiber.App) {
	router := app.Group("/deployment")
	router.Get("/", deployment.GetDeployment)
	router.Get("/invitations/validate", deployment.ValidateInvitation)
	router.Post("/invitations/accept", deployment.AcceptInvitation)
}
