package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/workspace"
)

func setupWorkspaceRoutes(app *fiber.App) {
	workspaceHandler := workspace.NewHandler()
	router := app.Group("/workspaces")

	router.Post("/", workspaceHandler.CreateWorkspace)
	router.Get("/:id", workspaceHandler.GetWorkspace)
	router.Put("/:id", workspaceHandler.UpdateWorkspace)
	router.Delete("/:id", workspaceHandler.DeleteWorkspace)
	
	// Member management
	router.Get("/:id/members", workspaceHandler.GetWorkspaceMembers)
	router.Post("/:id/members", workspaceHandler.InviteMember)
	router.Delete("/:id/members/:memberId", workspaceHandler.RemoveMember)
	
	// Role management
	router.Get("/:id/roles", workspaceHandler.GetWorkspaceRoles)
	router.Post("/:id/roles", workspaceHandler.CreateWorkspaceRole)
	router.Delete("/:id/roles/:roleId", workspaceHandler.DeleteWorkspaceRole)
	router.Post("/:workspaceId/members/:membershipId/roles/:roleId", workspaceHandler.AddWorkspaceMemberRole)
	router.Delete("/:workspaceId/members/:membershipId/roles/:roleId", workspaceHandler.RemoveWorkspaceMemberRole)
}
