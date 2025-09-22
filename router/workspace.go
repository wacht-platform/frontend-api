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
	router.Post("/:id/update", workspaceHandler.UpdateWorkspace)
	router.Post("/:id/delete", workspaceHandler.DeleteWorkspace)
	
	// Member management
	router.Get("/:id/members", workspaceHandler.GetWorkspaceMembers)
	router.Post("/:id/members", workspaceHandler.InviteMember)
	router.Post("/:id/members/:memberId/remove", workspaceHandler.RemoveMember)
	
	// Role management
	router.Get("/:id/roles", workspaceHandler.GetWorkspaceRoles)
	router.Post("/:id/roles", workspaceHandler.CreateWorkspaceRole)
	router.Post("/:id/roles/:roleId/delete", workspaceHandler.DeleteWorkspaceRole)
	router.Post("/:workspaceId/members/:membershipId/roles/:roleId/add", workspaceHandler.AddWorkspaceMemberRole)
	router.Post("/:workspaceId/members/:membershipId/roles/:roleId/remove", workspaceHandler.RemoveWorkspaceMemberRole)
}
