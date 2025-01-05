package model

import (
	"database/sql/driver"
	"time"

	"github.com/godruoyi/go-snowflake"
)

type SignInMethod string

const (
	SignInMethodPlain SignInMethod = "plain" // username + password
	SignInMethodSSO   SignInMethod = "sso"   // SSO
	Passkey           SignInMethod = "passkey"
)

func (s *SignInMethod) Scan(value any) error {
	*s = SignInMethod(value.(string))
	return nil
}

func (s SignInMethod) Value() (driver.Value, error) {
	return string(s), nil
}

type SignInAttempt struct {
	Model
	Email                              string             `json:"email"`
	SessionID                          uint               `json:"session_id"`
	Method                             SignInMethod       `json:"method"`
	SSOProvider                        SSOProvider        `json:"sso_provider"`
	ExpiresAt                          time.Time          `json:"expires_at"`
	FirstMethodAuthenticated           bool               `json:"first_method_authenticated"`
	SecondMethodAuthenticated          bool               `json:"second_method_authenticated"`
	SecondMethodAuthenticationRequired bool               `json:"second_method_authentication_required"`
	CurrenStep                         CurrentSessionStep `json:"current_step"`
	Completed                          bool               `json:"completed"`
}

func NewSignInAttempt(method SignInMethod) *SignInAttempt {
	return &SignInAttempt{
		Model: Model{
			ID: uint(snowflake.ID()),
		},
		Method:    method,
		ExpiresAt: time.Now().Add(time.Minute * 10),
	}
}
