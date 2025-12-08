package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/scim"
)

func setupSCIMRoutes(app *fiber.App) {
	scimHandler := scim.NewHandler()

	// SCIM routes are under /scim/v2/:connectionId
	// Each connection has its own SCIM endpoint with bearer token auth
	router := app.Group("/scim/v2/:connectionId")

	// Apply SCIM bearer token authentication middleware
	router.Use(scimHandler.AuthMiddleware)

	// Discovery endpoints
	router.Get("/ServiceProviderConfig", scimHandler.GetServiceProviderConfig)
	router.Get("/Schemas", scimHandler.GetSchemas)
	router.Get("/ResourceTypes", scimHandler.GetResourceTypes)

	// User endpoints
	router.Post("/Users", scimHandler.CreateUser)
	router.Get("/Users", scimHandler.ListUsers)
	router.Get("/Users/:userId", scimHandler.GetUser)
	router.Put("/Users/:userId", scimHandler.ReplaceUser)
	router.Patch("/Users/:userId", scimHandler.PatchUser)
	router.Delete("/Users/:userId", scimHandler.DeleteUser)

	// Group endpoints
	router.Post("/Groups", scimHandler.CreateGroup)
	router.Get("/Groups", scimHandler.ListGroups)
	router.Get("/Groups/:groupId", scimHandler.GetGroup)
	router.Patch("/Groups/:groupId", scimHandler.PatchGroup)
	router.Delete("/Groups/:groupId", scimHandler.DeleteGroup)
}
