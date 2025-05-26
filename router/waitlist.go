package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/waitlist"
)

func setupWaitlistRoutes(app *fiber.App) {
	waitlistHandler := waitlist.NewHandler()
	router := app.Group("/waitlist")

	router.Post("/join", waitlistHandler.JoinWaitlist)
}
