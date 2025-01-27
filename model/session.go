package model

import (
	"github.com/godruoyi/go-snowflake"
)

type CurrentSessionStep string

const (
	SessionStepVerifyEmail             CurrentSessionStep = "verify_email"
	SessionStepVerifyEmailOTP          CurrentSessionStep = "verify_email_otp"
	SessionStepVerifySecondFactor      CurrentSessionStep = "verify_second_factor"
	SessionStepVerifyPhone             CurrentSessionStep = "verify_phone"
	SessionStepVerifyPhoneOTP          CurrentSessionStep = "verify_phone_otp"
	SessionStepVerifyAuthenticator     CurrentSessionStep = "verify_authenticator"
	AddSecondFactor                    CurrentSessionStep = "add_second_factor"
	SessionStepPasswordResetInitiation CurrentSessionStep = "password_reset_initiation"
	SessionStepPasswordResetCompletion CurrentSessionStep = "password_reset_completion"
)

type Session struct {
	Model
	SignInAttempts []*SignInAttempt `json:"sign_in_attempts,omitempty"`
	SignIns        []*SignIn        `json:"sign_ins,omitempty"`
	ActiveSignInID uint             `json:"-"`
	ActiveSignIn   *SignIn          `json:"active_sign_in,omitempty"`
}

func NewSession() *Session {
	return &Session{
		Model: Model{
			ID: uint(snowflake.ID()),
		},
	}
}
