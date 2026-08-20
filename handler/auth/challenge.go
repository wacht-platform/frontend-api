package auth

import (
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/handler/captcha"
)

func requireChallenge(token string) error {
	if token == "" {
		return handler.ErrBadRequestBody
	}

	if err := captcha.VerifyToken(token); err != nil {
		return handler.ErrBadRequestBody
	}
	return nil
}
