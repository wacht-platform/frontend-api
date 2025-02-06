package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/user"
)

func setupUserRoutes(app *fiber.App) {
	userHandler := user.NewHandler()
	router := app.Group("/user")

	router.Get("/", userHandler.GetUser)
	// router.Post("/switch-sign-in", userHandler.GetActiveSignIn)
	// router.Post("/update-user", userHandler.UpdateUser)
}