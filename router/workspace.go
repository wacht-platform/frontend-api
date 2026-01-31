package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/workspace"
	"github.com/ilabs/wacht-fe/middleware"
)

func setupWorkspaceRoutes(app *fiber.App) {
	workspaceHandler := workspace.NewHandler()
	router := app.Group("/workspaces")

	// Public/Global workspace routes
	router.Post("/", middleware.EnforceB2BSettings, workspaceHandler.CreateWorkspace)

	// Workspace context routes
	workspaceContext := router.Group("/:id")
	workspaceContext.Use(middleware.SetWorkspaceContext)

	workspaceContext.Post("/update", workspaceHandler.UpdateWorkspace)
	workspaceContext.Post("/delete", workspaceHandler.DeleteWorkspace)

	// Member management
	workspaceContext.Get("/members", workspaceHandler.GetWorkspaceMembers)
	workspaceContext.Post("/members/:memberId/remove", workspaceHandler.RemoveMember)

	// Role management
	workspaceContext.Get("/roles", workspaceHandler.GetWorkspaceRoles)
	workspaceContext.Post("/roles", workspaceHandler.CreateWorkspaceRole)
	workspaceContext.Post("/roles/:roleId/delete", workspaceHandler.DeleteWorkspaceRole)

	// Member Role management
	workspaceContext.Post("/members/:membershipId/roles/:roleId/add", workspaceHandler.AddWorkspaceMemberRole)
	workspaceContext.Post("/members/:membershipId/roles/:roleId/remove", workspaceHandler.RemoveWorkspaceMemberRole)
}
