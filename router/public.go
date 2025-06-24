package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler/deployment"
)

func setupPublicRoutes(app *fiber.App) {
	wellknown := app.Group("/.well-known")

	wellknown.Get("/meta", deployment.GetMetadata)
	wellknown.Get("/jwk", deployment.GetJwk)
}
