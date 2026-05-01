package router

import (
	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/handler/ai"
)

func setupAiRoutes(app *fiber.App) {
	h := ai.NewHandler()

	aiGroup := app.Group("/ai")
	aiGroup.Get("/session", h.GetSession)
	aiGroup.Get("/projects", h.ListActorProjects)
	aiGroup.Get("/projects/search", h.SearchActorProjects)
	aiGroup.Post("/projects", h.CreateActorProject)
	aiGroup.Post("/threads", h.CreateActorThread)
	aiGroup.Get("/threads/search", h.SearchActorThreads)
	aiGroup.Get("/mcp-servers", h.ListActorMcpServers)
	aiGroup.Post("/mcp-servers/:mcp_server_id/connect", h.ConnectActorMcpServer)
	aiGroup.Post("/mcp-servers/:mcp_server_id/disconnect", h.DisconnectActorMcpServer)
	aiGroup.Get("/projects/:project_id", h.GetActorProject)
	aiGroup.Post("/projects/:project_id/update", h.UpdateActorProject)
	aiGroup.Post("/projects/:project_id/archive", h.ArchiveActorProject)
	aiGroup.Post("/projects/:project_id/unarchive", h.UnarchiveActorProject)
	aiGroup.Get("/projects/:project_id/board", h.GetProjectBoard)
	aiGroup.Get("/projects/:project_id/board/items", h.ListProjectBoardItems)
	aiGroup.Post("/projects/:project_id/board/items", h.CreateProjectBoardItem)
	aiGroup.Get("/projects/:project_id/board/items/:item_id", h.GetBoardItem)
	aiGroup.Get("/projects/:project_id/board/items/:item_id/assignments", h.ListBoardItemAssignments)
	aiGroup.Get("/projects/:project_id/board/items/:item_id/filesystem", h.ListBoardItemTaskWorkspaceFiles)
	aiGroup.Get("/projects/:project_id/board/items/:item_id/filesystem/file", h.GetBoardItemTaskWorkspaceFileContent)
	aiGroup.Post("/projects/:project_id/board/items/:item_id/update", h.UpdateBoardItem)
	aiGroup.Post("/projects/:project_id/board/items/:item_id/archive", h.ArchiveBoardItem)
	aiGroup.Post("/projects/:project_id/board/items/:item_id/cancel", h.CancelBoardItem)
	aiGroup.Post("/projects/:project_id/board/items/:item_id/unarchive", h.UnarchiveBoardItem)
	aiGroup.Get("/projects/:project_id/threads", h.ListProjectThreads)
	aiGroup.Post("/projects/:project_id/threads", h.CreateProjectThread)
	aiGroup.Post("/threads/:thread_id/update", h.UpdateThread)
	aiGroup.Post("/threads/:thread_id/archive", h.ArchiveThread)
	aiGroup.Post("/threads/:thread_id/unarchive", h.UnarchiveThread)
	aiGroup.Get("/threads/:thread_id", h.GetThread)
	aiGroup.Get("/threads/:thread_id/assignments", h.ListThreadAssignments)
	aiGroup.Get("/threads/:thread_id/task-graphs", h.ListThreadTaskGraphs)
	aiGroup.Get("/threads/:thread_id/messages", h.GetThreadMessages)
	aiGroup.Get("/threads/:thread_id/filesystem", h.ListThreadFilesystemEntries)
	aiGroup.Get("/threads/:thread_id/filesystem/file", h.GetThreadFilesystemFileContent)
	aiGroup.Get("/threads/:thread_id/stream", h.Stream)
	aiGroup.Post("/threads/:thread_id/run", h.RunThread)
}
