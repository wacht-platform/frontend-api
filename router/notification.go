package router

import (
	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/handler/notification"
)

func setupNotificationRoutes(app *fiber.App) {
	router := app.Group("/notifications")

	router.Get("/", notification.List)
	router.Get("/scope-unread", notification.GetScopeUnread)
	router.Post("/:id/read", notification.MarkAsRead)
	router.Post("/:id/unread", notification.MarkAsUnread)
	router.Post("/:id/archive", notification.Archive)
	router.Post("/:id/star", notification.Star)
	router.Post("/mark-all-read", notification.MarkAllAsRead)
	router.Post("/archive-all-read", notification.ArchiveAllRead)

	router.Use("/stream", func(c *fiber.Ctx) error {
		if websocket.IsWebSocketUpgrade(c) {
			return c.Next()
		}
		return handler.SendBadRequest(c, nil, "WebSocket upgrade required")
	})
	router.Get("/stream", websocket.New(notification.Stream))
}
