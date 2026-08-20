package auth

import (
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/handler/captcha"
)

type ChallengeTokenRequest struct {
	ChallengeToken string `form:"challenge_token" json:"challenge_token"`
}

func requireChallengeFromRequest(c fiber.Ctx) error {
	b, validation := handler.Validate[ChallengeTokenRequest](c)
	if validation != nil {
		return handler.ErrBadRequestBody
	}
	return requireChallenge(b.ChallengeToken)
}

func requireChallenge(token string) error {
	if strings.TrimSpace(token) == "" {
		return handler.ErrBadRequestBody
	}

	if err := captcha.VerifyToken(token); err != nil {
		return handler.ErrBadRequestBody
	}
	return nil
}
