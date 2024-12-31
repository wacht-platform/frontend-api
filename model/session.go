package model

import (
	"github.com/godruoyi/go-snowflake"
)

type CurrentSessionStep string

const (
	SessionStepVerifyPassword      CurrentSessionStep = "verify_password"
	SessionStepVerifyEmail         CurrentSessionStep = "verify_email"
	SessionStepVerifyEmailOTP      CurrentSessionStep = "verify_email_otp"
	SessionStepVerifySecondFactor  CurrentSessionStep = "verify_second_factor"
	SessionStepVerifyPhone         CurrentSessionStep = "verify_phone"
	SessionStepVerifyPhoneOTP      CurrentSessionStep = "verify_phone_otp"
	SessionStepVerifyAuthenticator CurrentSessionStep = "verify_authenticator"
)

type Session struct {
	Model
	SignInAttempts []SignInAttempt `json:"sign_in_attempts"`
	ActiveSignIns  []SignIn        `json:"active_sign_ins"`
}

func NewSession() *Session {
	return &Session{
		Model: Model{
			ID: uint(snowflake.ID()),
		},
	}
}
