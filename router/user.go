package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/user"
)

func setupUserRoutes(
	app *fiber.App,
) {
	userHandler := user.NewHandler()
	router := app.Group("/me")

	router.Get("/", userHandler.GetUser)
	router.Post("/", userHandler.UpdateUser)
	router.Get("/organization-memberships", userHandler.GetUserOrganizationMemberships)
	router.Get("/workspace-memberships", userHandler.GetUserWorkspaceMemberships)
	router.Get("/email-addresses", userHandler.GetUserEmailAddresses)
	router.Get("/email-addresses/:id", userHandler.GetUserEmailAddress)
	router.Post("/email-addresses/:id/delete", userHandler.DeleteUserEmailAddress)
	router.Post("/email-addresses", userHandler.CreateUserEmailAddress)
	router.Post("/email-addresses/:id/prepare-verification", userHandler.PrepareEmailVerification)
	router.Post("/email-addresses/:id/attempt-verification", userHandler.AttemptEmailVerification)
	router.Get("/phone-numbers", userHandler.GetUserPhoneNumbers)
	router.Get("/phone-numbers/:id", userHandler.GetPhoneNumber)
	router.Post("/phone-numbers", userHandler.AddPhoneNumber)
	router.Post("/phone-numbers/:id/delete", userHandler.DeletePhoneNumber)
	router.Post("/phone-numbers/:id/prepare-verification", userHandler.PreparePhoneVerification)
	router.Post("/phone-numbers/:id/attempt-verification", userHandler.AttemptPhoneVerification)
	router.Post("/profile-picture", userHandler.UploadProfilePicture)
	router.Post("/authenticator", userHandler.GenerateAuthenticator)
	router.Post("/authenticator/attempt-verification", userHandler.VerifyAuthenticator)
	router.Post("/authenticator/:id/delete", userHandler.DeleteAuthenticator)
	router.Post("/backup-codes", userHandler.GenerateBackupCodes)
	router.Post("/backup-codes/regenerate", userHandler.RegenerateBackupCodes)
	router.Get("/signins", userHandler.GetUserSignins)
	router.Post("/signins/:id/signout", userHandler.SignOutFromSession)
	router.Post("/email-addresses/:id/make-primary", userHandler.MakeEmailPrimary)
	router.Post("/phone-numbers/:id/make-primary", userHandler.MakePhonePrimary)
	router.Post("/update-password", userHandler.UpdatePassword)
	router.Post("/remove-password", userHandler.RemovePassword)
	router.Post("/account/delete", userHandler.DeleteAccount)
	router.Post("/social-connections/:id/disconnect", userHandler.DisconnectSocialConnection)
	router.Post("/init-sso-connection", userHandler.InitConnectSocial)
	router.Post("/sso-connection-callback", userHandler.ConnectSocialCallback)
	router.Get("/passkeys", userHandler.GetPasskeys)
	router.Post("/passkeys/register/begin", userHandler.BeginPasskeyRegistration)
	router.Post("/passkeys/register/finish", userHandler.FinishPasskeyRegistration)
	router.Post("/passkeys/:id/delete", userHandler.DeletePasskey)
	router.Patch("/passkeys/:id", userHandler.RenamePasskey)
}
