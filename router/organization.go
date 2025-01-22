package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/organization"
)

func setupOrganizationRoutes(app *fiber.App) {
	orgHandler := organization.NewHandler()
	router := app.Group("/organizations")

	router.Post("/", orgHandler.CreateOrganization)
	router.Get("/:id", orgHandler.GetOrganization)
	router.Put("/:id", orgHandler.UpdateOrganization)
	router.Delete("/:id", orgHandler.DeleteOrganization)
	router.Post("/:id/members", orgHandler.InviteMember)
	router.Delete("/:id/members/:memberId", orgHandler.RemoveMember)
}
