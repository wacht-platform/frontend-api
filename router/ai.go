package router

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/limiter"
	"github.com/wacht-platform/frontend-api/handler"
	aihandler "github.com/wacht-platform/frontend-api/handler/ai"
	"github.com/wacht-platform/frontend-api/middleware"
	"github.com/wacht-platform/frontend-api/service"
)

func setupAiRoutes(app *fiber.App) {
	h := aihandler.NewHandler()

	natsService := service.GetNATS()
	aiGroup := app.Group("/ai")
	aiGroup.Use(limiter.New(limiter.Config{
		Max:        100,
		Expiration: 1 * time.Minute,
		Storage:    middleware.NewNatsStorage(natsService),
		KeyGenerator: func(c fiber.Ctx) string {
			now := time.Now()
			return fmt.Sprintf("%s:%s:%d:%d", c.IP(), c.Path(), now.Hour(), now.Minute())
		},
		LimitReached: func(c fiber.Ctx) error {
			return handler.SendTooManyRequests(
				c,
				nil,
				"Too many requests. Please try again later.",
				handler.ErrTooManyRequests,
			)
		},
	}))
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
	aiGroup.Get("/projects/:project_id/board/items/:item_id/filesystem/download", h.DownloadBoardItemTaskWorkspaceFile)
	aiGroup.Post("/projects/:project_id/board/items/:item_id/update", h.UpdateBoardItem)
	aiGroup.Post("/projects/:project_id/board/items/:item_id/archive", h.ArchiveBoardItem)
	aiGroup.Post("/projects/:project_id/board/items/:item_id/cancel", h.CancelBoardItem)
	aiGroup.Post("/projects/:project_id/board/items/:item_id/answer", h.AnswerBoardItemQuestion)
	aiGroup.Post("/projects/:project_id/board/items/:item_id/approval", h.ApproveBoardItemTool)
	aiGroup.Post("/projects/:project_id/board/items/:item_id/unarchive", h.UnarchiveBoardItem)
	aiGroup.Get("/projects/:project_id/board/items/:item_id/comments", h.ListBoardItemComments)
	aiGroup.Post("/projects/:project_id/board/items/:item_id/comments", h.CreateBoardItemComment)
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
	aiGroup.Post("/threads/:thread_id/messages/answer", h.AnswerThreadQuestion)
}
