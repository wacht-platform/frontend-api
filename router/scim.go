package router

import (
	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/handler/scim"
)

func setupSCIMRoutes(app *fiber.App) {
	scimHandler := scim.NewHandler()

	router := app.Group("/scim/v2/:connectionId")

	router.Use(scimHandler.AuthMiddleware)

	router.Get("/ServiceProviderConfig", scimHandler.GetServiceProviderConfig)
	router.Get("/Schemas", scimHandler.GetSchemas)
	router.Get("/ResourceTypes", scimHandler.GetResourceTypes)

	router.Post("/Users", scimHandler.CreateUser)
	router.Get("/Users", scimHandler.ListUsers)
	router.Get("/Users/:userId", scimHandler.GetUser)
	router.Put("/Users/:userId", scimHandler.ReplaceUser)
	router.Patch("/Users/:userId", scimHandler.PatchUser)
	router.Delete("/Users/:userId", scimHandler.DeleteUser)

	router.Post("/Groups", scimHandler.CreateGroup)
	router.Get("/Groups", scimHandler.ListGroups)
	router.Get("/Groups/:groupId", scimHandler.GetGroup)
	router.Put("/Groups/:groupId", scimHandler.ReplaceGroup)
	router.Patch("/Groups/:groupId", scimHandler.PatchGroup)
	router.Delete("/Groups/:groupId", scimHandler.DeleteGroup)
}
