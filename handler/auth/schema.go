package auth

import (
	"github.com/ilabs/wacht-fe/model"
)

// SignInRequest represents the sign in request payload
type SignInRequest struct {
	Username string `form:"username"`
	Email    string `form:"email"`
	Phone    string `form:"phone"`
	Password string `form:"password"`
}

// SignUpRequest represents the sign up request payload
type SignUpRequest struct {
	FirstName   string `form:"firstName"`
	LastName    string `form:"lastName"`
	Username    string `form:"username"`
	PhoneNumber string `form:"phoneNumber"`
	Email       string `form:"email"`
	Password    string `form:"password"`
}

// SSOCallbackResponse represents the SSO callback response
type SSOCallbackResponse struct {
	Session model.Session `json:"session"`
}

// AuthMethodsResponse represents the auth methods response
type AuthMethodsResponse struct {
	AuthSettings model.AuthSettings `json:"auth_settings"`
}

// InitSSOResponse represents the SSO initialization response
type InitSSOResponse struct {
	OAuthURL string        `json:"oauth_url"`
	Session  model.Session `json:"session"`
}

type VerifyOTPRequest struct {
	Email string `json:"email"`
	Passcode string `json:"otp"`
}

type PrepareVerificationRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Email string `json:"email"`
	Password string `json:"password"`
}

type SetupAuthenticatorRequest struct {
	Email string `json:"email"`
}
