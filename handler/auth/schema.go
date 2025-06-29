package auth

import (
	"github.com/ilabs/wacht-fe/model"
)

type SignInRequest struct {
	Username string             `form:"username"`
	Email    string             `form:"email"`
	Phone    string             `form:"phone"`
	Password string             `form:"password"`
	Strategy model.SignInMethod `form:"strategy"`
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

type InitSSOResponse struct {
	OAuthURL string        `json:"oauth_url"`
	Session  model.Session `json:"session"`
}

type VerifyOTPRequest struct {
	VerificationCode string `form:"verification_code"`
}

type PrepareVerificationRequest struct {
	Email string `form:"email"`
}

type ForgotPasswordRequest struct {
	Email string `form:"email"`
}

type ResetPasswordRequest struct {
	Email    string `form:"email"`
	Password string `form:"password"`
	OTP      string `form:"otp"`
}

type SetupAuthenticatorRequest struct {
	Email string `form:"email"`
}

type ProfileCompletionData struct {
	FirstName   string `form:"first_name"`
	LastName    string `form:"last_name"`
	Username    string `form:"username"`
	Email       string `form:"email"`
	PhoneNumber string `form:"phone_number"`
}

type IPLocation struct {
	Status        string  `json:"status"`
	Continent     string  `json:"continent"`
	ContinentCode string  `json:"continentCode"`
	Country       string  `json:"country"`
	CountryCode   string  `json:"countryCode"`
	Region        string  `json:"region"`
	RegionName    string  `json:"regionName"`
	City          string  `json:"city"`
	Zip           string  `json:"zip"`
	Lat           float64 `json:"lat"`
	Long          float64 `json:"lon"`
	Timezone      string  `json:"timezone"`
	ISP           string  `json:"isp"`
}

type SecondFactorVerificationRequest struct {
	VerificationCode string `form:"verification_code" validate:"required"`
	Method           string `form:"method" validate:"required,oneof=totp backup_code"`
}

type SecondFactorSetupRequest struct {
	AuthenticatorID string   `form:"authenticator_id" validate:"required"`
	Codes           []string `form:"codes" validate:"required,min=2,max=2"`
}
