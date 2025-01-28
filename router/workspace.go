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
	router.Post("/:id/members", workspaceHandler.InviteMember)
	router.Delete(
		"/:id/members/:memberId",
		workspaceHandler.RemoveMember,
	)
}
