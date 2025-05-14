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
	SigninAttempts []*SignInAttempt `json:"signin_attempts,omitempty"`
	Signins        []*Signin        `json:"signins,omitempty"`
	SignupAttempts []*SignupAttempt `json:"signup_attempts,omitempty"`
	ActiveSigninID uint64           `json:"-"`
	ActiveSignin   *Signin          `json:"active_signin,omitempty"`
}

func NewSession() *Session {
	return &Session{
		Model: Model{
			ID: snowflake.ID(),
		},
	}
}
