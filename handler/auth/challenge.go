package auth

import (
	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/handler/captcha"
)

func requireChallenge(c fiber.Ctx, token string) error {
	if token == "" {
		token = c.FormValue("challenge_token")
	}
	if token == "" {
		token = c.Query("challenge_token")
	}
	if err := captcha.VerifyToken(token); err != nil {
		return handler.SendForbidden(c, nil, "Challenge verification failed", handler.ErrTooManyRequests)
	}
	return nil
}
