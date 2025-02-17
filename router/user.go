package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/user"
)

func setupUserRoutes(app *fiber.App) {
	userHandler := user.NewHandler()
	router := app.Group("/me")

	router.Get("/", userHandler.GetUser)
	router.Patch("/", userHandler.UpdateUser)
	router.Get("/email-addresses", userHandler.GetUserEmailAddresses)
	router.Get(
		"/email-addresses/:id",
		userHandler.GetUserEmailAddress,
	)
	router.Delete(
		"/email-addresses/:id",
		userHandler.DeleteUserEmailAddress,
	)
	router.Post(
		"/email-addresses",
		userHandler.CreateUserEmailAddress,
	)
	router.Post(
		"/email-addresses/:id/prepare-verification",
		userHandler.PrepareEmailVerification,
	)
	router.Post(
		"/email-addresses/:id/attempt-verification",
		userHandler.AttemptEmailVerification,
	)
}
