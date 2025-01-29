package model

import (
	"github.com/godruoyi/go-snowflake"
)

type SignInAttemptStep string

const (
	SignInAttemptStepVerifyEmail             SignInAttemptStep = "verify_email"
	SignInAttemptStepVerifyEmailOTP          SignInAttemptStep = "verify_email_otp"
	SignInAttemptStepVerifySecondFactor      SignInAttemptStep = "verify_second_factor"
	SignInAttemptStepVerifyPhone             SignInAttemptStep = "verify_phone"
	SignInAttemptStepVerifyPhoneOTP          SignInAttemptStep = "verify_phone_otp"
	SignInAttemptStepPasswordResetInitiation SignInAttemptStep = "password_reset_initiation"
	SignInAttemptStepPasswordResetCompletion SignInAttemptStep = "password_reset_completion"
)

type Session struct {
	Model
	SigninAttempts []*SignInAttempt `json:"sign_in_attempts,omitempty"`
	SignIns        []*SignIn        `json:"sign_ins,omitempty"`
	SignupAttempts []*SignupAttempt `json:"signup_attempts,omitempty"`
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
