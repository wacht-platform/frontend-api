package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/workspace"
	"github.com/ilabs/wacht-fe/middleware"
)

func setupWorkspaceRoutes(app *fiber.App) {
	workspaceHandler := workspace.NewHandler()
	router := app.Group("/workspaces")

	router.Use(middleware.EnforceB2BSettings)

	router.Post("/", workspaceHandler.CreateWorkspace)
	router.Post("/:id/update", workspaceHandler.UpdateWorkspace)
	router.Post("/:id/delete", workspaceHandler.DeleteWorkspace)

	// Member management
	router.Get("/:id/members", workspaceHandler.GetWorkspaceMembers)
	router.Post("/:id/members/:memberId/remove", workspaceHandler.RemoveMember)

	// Role management
	router.Get("/:id/roles", workspaceHandler.GetWorkspaceRoles)
	router.Post("/:id/roles", workspaceHandler.CreateWorkspaceRole)
	router.Post("/:id/roles/:roleId/delete", workspaceHandler.DeleteWorkspaceRole)
	router.Post("/:workspaceId/members/:membershipId/roles/:roleId/add", workspaceHandler.AddWorkspaceMemberRole)
	router.Post("/:workspaceId/members/:membershipId/roles/:roleId/remove", workspaceHandler.RemoveWorkspaceMemberRole)
}
