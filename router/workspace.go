package router

import (
	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/handler/workspace"
	"github.com/wacht-platform/frontend-api/middleware"
)

func setupWorkspaceRoutes(app *fiber.App) {
	workspaceHandler := workspace.NewHandler()
	router := app.Group("/workspaces")

	router.Post("/", workspaceHandler.CreateWorkspace)
	workspaceContext := router.Group("/:id")
	workspaceContext.Use(middleware.SetWorkspaceContext)
	workspaceContext.Post("/update", workspaceHandler.UpdateWorkspace)
	workspaceContext.Post("/delete", workspaceHandler.DeleteWorkspace)
	workspaceContext.Get("/members", workspaceHandler.GetWorkspaceMembers)
	workspaceContext.Post("/members/:memberId/remove", workspaceHandler.RemoveMember)
	workspaceContext.Get("/roles", workspaceHandler.GetWorkspaceRoles)
	workspaceContext.Post("/roles", workspaceHandler.CreateWorkspaceRole)
	workspaceContext.Post("/roles/:roleId/delete", workspaceHandler.DeleteWorkspaceRole)
	workspaceContext.Post("/members/:membershipId/roles/:roleId/add", workspaceHandler.AddWorkspaceMemberRole)
	workspaceContext.Post("/members/:membershipId/roles/:roleId/remove", workspaceHandler.RemoveWorkspaceMemberRole)
}
