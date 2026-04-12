package router

import (
	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/handler/waitlist"
)

func setupWaitlistRoutes(app *fiber.App) {
	waitlistHandler := waitlist.NewHandler()
	router := app.Group("/waitlist")

	router.Post("/join", waitlistHandler.JoinWaitlist)
}
