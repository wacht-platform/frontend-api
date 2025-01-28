package auth

import (
	"github.com/ilabs/wacht-fe/model"
)

type SignInRequest struct {
	Username string `form:"username"`
	Email    string `form:"email"`
	Phone    string `form:"phone"`
	Password string `form:"password"`
}

type SignUpRequest struct {
	FirstName   string `form:"first_name"`
	LastName    string `form:"last_name"`
	Username    string `form:"username"`
	PhoneNumber string `form:"phone_number"`
	Email       string `form:"email"`
	Password    string `form:"password"`
}

type SSOCallbackResponse struct {
	Session model.Session `json:"session"`
}

type AuthMethodsResponse struct {
	AuthSettings model.AuthSettings `json:"auth_settings"`
}

type InitSSOResponse struct {
	OAuthURL string        `json:"oauth_url"`
	Session  model.Session `json:"session"`
}

type VerifyOTPRequest struct {
	VerificationCode string `json:"verification_code"`
}

type PrepareVerificationRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SetupAuthenticatorRequest struct {
	Email string `json:"email"`
}
