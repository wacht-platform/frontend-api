package router

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/limiter"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/middleware"
	"github.com/wacht-platform/frontend-api/service"
	"golang.org/x/net/publicsuffix"
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
	setupAiRoutes(app)
	setupExternalConnectionRoutes(app)
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
		Next: func(c fiber.Ctx) bool {
			return c.Method() == fiber.MethodGet && c.Path() == "/session/token"
		},
		KeyGenerator: func(c fiber.Ctx) string {
			now := time.Now()
			return fmt.Sprintf("%s:%s:%d:%d", c.IP(), c.Path(), now.Hour(), now.Minute())
		},
		LimitReached: func(c fiber.Ctx) error {
			return handler.SendTooManyRequests(
				c,
				nil,
				"Too many requests. Please try again later.",
				handler.ErrTooManyRequests,
			)
		},
	}))
	app.Use(middleware.SetRequestPrelude)
	app.Use(func(c fiber.Ctx) error {
		cfg := corsSettings(c)
		return cors.New(cfg)(c)
	})
}

func corsSettings(c fiber.Ctx) cors.Config {
	deployment := handler.GetDeployment(c)

	if deployment.IsProduction() {
		return cors.Config{
			AllowOriginsFunc: func(origin string) bool {
				parsedOrigin, err := url.Parse(origin)
				if err != nil {
					return false
				}

				originHost := strings.ToLower(strings.TrimSpace(parsedOrigin.Hostname()))
				frontendHost := strings.ToLower(strings.TrimSpace(deployment.FrontendHost))
				if originHost == "" {
					return false
				}

				if frontendHost != "" && (originHost == frontendHost ||
					strings.HasSuffix(originHost, "."+frontendHost)) {
					return true
				}

				if frontendHost == "" {
					return false
				}

				originSite, err := publicsuffix.EffectiveTLDPlusOne(originHost)
				if err != nil {
					return false
				}

				frontendSite, err := publicsuffix.EffectiveTLDPlusOne(frontendHost)
				if err != nil {
					return false
				}

				return originSite == frontendSite
			},
			AllowCredentials: true,
			AllowMethods:     []string{"GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"},
		}
	}

	return cors.Config{
		AllowOriginsFunc: func(origin string) bool {
			return true
		},
		ExposeHeaders:    []string{"X-Development-Session"},
		AllowMethods:     []string{"GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowCredentials: true,
	}
}
