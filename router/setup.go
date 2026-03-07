package router

import (
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/middleware"
	"github.com/wacht-platform/frontend-api/service"
)

func Setup(app *fiber.App) {
	setupMiddleware(app)
	setupRoutes(app)
}

func setupRoutes(app *fiber.App) {
	setupPublicRoutes(app)
	setupOAuthConsentRoutes(app)
	setupAuthRoutes(app)
	setupDeploymentRoutes(app)
	setupSessionRoutes(app)
	setupOrganizationRoutes(app)
	setupWorkspaceRoutes(app)
	setupUserRoutes(app)
	setupWaitlistRoutes(app)
	setupNotificationRoutes(app)
	setupAgentRoutes(app)
	setupWebhookAppRoutes(app)
	setupApiAuthAppRoutes(app)
	setupSCIMRoutes(app)
}

func setupMiddleware(app *fiber.App) {
	app.Use(recover.New())
	natsService := service.GetNATS()
	app.Use(limiter.New(limiter.Config{
		Max:        20,
		Expiration: 1 * time.Minute,
		Storage:    middleware.NewNatsStorage(natsService),
		KeyGenerator: func(c *fiber.Ctx) string {
			now := time.Now()
			return fmt.Sprintf("%s:%s:%d:%d", c.IP(), c.Path(), now.Hour(), now.Minute())
		},
		LimitReached: func(c *fiber.Ctx) error {
			return handler.SendTooManyRequests(
				c,
				nil,
				"Too many requests. Please try again later.",
				handler.ErrTooManyRequests,
			)
		},
	}))
	app.Use(middleware.SetRequestPrelude)
	app.Use(func(c *fiber.Ctx) error {
		cfg := corsSettings(c)
		return cors.New(cfg)(c)
	})
}

func corsSettings(c *fiber.Ctx) cors.Config {
	deployment := handler.GetDeployment(c)

	if deployment.IsProduction() {
		return cors.Config{
			AllowOriginsFunc: func(origin string) bool {
				parts := strings.Split(deployment.FrontendHost, ".")
				if len(parts) < 2 {
					return false
				}
				return strings.HasSuffix(origin, strings.Join(parts[len(parts)-2:], "."))
			},
			AllowCredentials: true,
			AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		}
	}

	return cors.Config{
		AllowOriginsFunc: func(origin string) bool {
			return true
		},
		ExposeHeaders:    "X-Development-Session",
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		AllowCredentials: true,
	}
}
