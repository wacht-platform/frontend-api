package router

import (
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/ilabs/wacht-fe/handler/auth"
	"github.com/ilabs/wacht-fe/handler/deployment"
	"github.com/ilabs/wacht-fe/handler/organization"
	"github.com/ilabs/wacht-fe/handler/session"
	"github.com/ilabs/wacht-fe/handler/workspace"
	"github.com/ilabs/wacht-fe/middleware"
)

func Setup(app *fiber.App) {
	setupMiddleware(app)
	setupRoutes(app)
}

func setupRoutes(app *fiber.App) {
	auth := app.Group("/auth")
	setupAuthRoutes(auth)

	deployment := app.Group("/deployment")
	setupDeploymentRoutes(deployment)

	sessions := app.Group("/session")
	setupSessionRoutes(sessions)

	organizations := app.Group("/organizations")
	setupOrganizationRoutes(organizations)

	workspaces := app.Group("/workspaces")
	setupWorkspaceRoutes(workspaces)
}

func setupMiddleware(app *fiber.App) {
	// app.Use(recover.New())
	app.Use(cors.New(corsSettings()))
	app.Use(middleware.SetDeploymentMiddleware)
	app.Use(middleware.SetSessionMiddleware)
	app.Use(middleware.RateLimiter)
}

func corsSettings() cors.Config {
	corsSetting := cors.ConfigDefault
	// corsSetting.AllowCredentials = os.Getenv("MODE") == "development"

	if os.Getenv("MODE") == "staging" {
		corsSetting.AllowHeaders = "X-Development-Session"
		corsSetting.ExposeHeaders = "X-Development-Session"
	}

	return corsSetting
}

func setupAuthRoutes(router fiber.Router) {
	authHandler := auth.NewHandler()

	router.Post("/signin", authHandler.SignIn)
	router.Post("/signup", authHandler.SignUp)
	router.Post("/sso", authHandler.InitSSO)
	router.Get("/sso-callback", authHandler.SSOCallback)
	router.Get("/identifier-availability", authHandler.CheckIdentifierAvailability)
	router.Get("/prepare-authentication", authHandler.SetupAuthenticator)
	router.Post("/prepare-verification", authHandler.PrepareVerification)
	router.Post("/verify-otp", authHandler.VerifyOTP)
	router.Post("/prepare-reset-password", authHandler.PreparePasswordReset)
	router.Post("/reset-password", authHandler.ResetPassword)
}

func setupDeploymentRoutes(router fiber.Router) {
	router.Get("/", deployment.GetDeployment)
}

func setupSessionRoutes(router fiber.Router) {
	sessionHandler := session.NewHandler()

	router.Get("/", sessionHandler.GetCurrentSession)
	router.Post("/switch-sign-in", sessionHandler.SwitchActiveSignIn)
	router.Post("/sign-out", sessionHandler.SignOut)
}

func setupOrganizationRoutes(router fiber.Router) {
	orgHandler := organization.NewHandler()

	router.Post("/", orgHandler.CreateOrganization)
	router.Get("/:id", orgHandler.GetOrganization)
	router.Put("/:id", orgHandler.UpdateOrganization)
	router.Delete("/:id", orgHandler.DeleteOrganization)
	router.Post("/:id/members", orgHandler.InviteMember)
	router.Delete("/:id/members/:memberId", orgHandler.RemoveMember)
}

func setupWorkspaceRoutes(router fiber.Router) {
	workspaceHandler := workspace.NewHandler()

	router.Post("/", workspaceHandler.CreateWorkspace)
	router.Get("/:id", workspaceHandler.GetWorkspace)
	router.Put("/:id", workspaceHandler.UpdateWorkspace)
	router.Delete("/:id", workspaceHandler.DeleteWorkspace)
	router.Post("/:id/members", workspaceHandler.InviteMember)
	router.Delete("/:id/members/:memberId", workspaceHandler.RemoveMember)
}
