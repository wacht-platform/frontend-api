package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/notification"
)

func setupNotificationRoutes(app *fiber.App) {
	router := app.Group("/notifications")

	router.Get("/", notification.List)
	router.Get("/scope-unread", notification.GetScopeUnread)
	router.Get("/:id", notification.Get)
	router.Post("/:id/read", notification.MarkAsRead)
	router.Post("/:id/unread", notification.MarkAsUnread)
	router.Post("/:id/archive", notification.Archive)
	router.Post("/:id/star", notification.Star)
	router.Post("/mark-all-read", notification.MarkAllAsRead)
	router.Post("/archive-all-read", notification.ArchiveAllRead)
}
