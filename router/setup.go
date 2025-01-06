package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/ilabs/wacht-fe/handler/auth"
	"github.com/ilabs/wacht-fe/handler/deployment"
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
}

func setupMiddleware(app *fiber.App) {
	app.Use(middleware.SetDeploymentMiddleware)
	app.Use(recover.New())
	app.Use(cors.New(corsSettings()))
}

func corsSettings() cors.Config {
	corsSetting := cors.ConfigDefault
	// corsSetting.AllowCredentials = os.Getenv("MODE") == "development"

	return corsSetting
}

func setupAuthRoutes(router fiber.Router) {
	router.Post("/signin", auth.SignIn)
	router.Post("/signup", auth.SignUp)
	router.Get("/methods", auth.AuthMethods)
	router.Post("/sso", auth.InitSSO)
	router.Get("/sso-callback", auth.SSOCallback)
	// router.Post("/otp-verify", auth.VerifyOTP)
}

func setupDeploymentRoutes(router fiber.Router) {
	router.Get("/", deployment.GetDeployment)
}
