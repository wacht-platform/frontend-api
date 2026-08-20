package auth

import (
	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/handler/captcha"
)

func requireChallenge(c fiber.Ctx, token string) error {
	if token == "" {
		return handler.SendForbidden(c, nil, "Challenge verification failed", handler.ErrTooManyRequests)
	}

	if err := captcha.VerifyToken(token); err != nil {
		return handler.SendForbidden(c, nil, "Challenge verification failed", handler.ErrTooManyRequests)
	}
	return nil
}
