package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/notification"
)

func setupNotificationRoutes(app *fiber.App) {
	router := app.Group("/notifications")

	// List and count endpoints
	router.Get("/", notification.List)
	router.Get("/unread-count", notification.GetUnreadCount)
	router.Get("/channel-counts", notification.GetChannelCounts)

	// Single notification operations
	router.Get("/:id", notification.Get)
	router.Post("/:id/read", notification.MarkAsRead)
	router.Post("/:id/delete", notification.Delete)

	// Bulk operations
	router.Post("/mark-all-read", notification.MarkAllAsRead)
}
