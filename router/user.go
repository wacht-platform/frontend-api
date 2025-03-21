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
	router.Get("/phone-numbers", userHandler.GetUserPhoneNumbers)
	router.Get(
		"/phone-numbers/:id",
		userHandler.GetPhoneNumber,
	)
	router.Post("/phone-numbers", userHandler.AddPhoneNumber)
	router.Delete(
		"/phone-numbers/:id",
		userHandler.DeletePhoneNumber,
	)
	router.Post(
		"/phone-numbers/:id/prepare-verification",
		userHandler.PreparePhoneVerification,
	)
	router.Post(
		"/phone-numbers/:id/attempt-verification",
		userHandler.AttemptPhoneVerification,
	)
	router.Post("/profile-picture", userHandler.UploadProfilePicture)

	router.Post("/authenticator", userHandler.GenerateAuthenticator)
	router.Post("/authenticator/attempt-verification", userHandler.VerifyAuthenticator)
	router.Delete("/authenticator/:id", userHandler.DeleteAuthenticator)

	router.Post("/backup-codes", userHandler.GenerateBackupCodes)
	router.Post("/signins", userHandler.GetUserSignins)
	router.Patch("/signins/:id/signout", userHandler.SignOutFromSession)
}
