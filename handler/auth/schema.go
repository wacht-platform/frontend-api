package auth

import (
	"github.com/wacht-platform/frontend-api/model"
)

type SignInRequest struct {
	Username         string             `form:"username"`
	Email            string             `form:"email"`
	Phone            string             `form:"phone"`
	PhoneCountryCode string             `form:"phone_country_code"`
	Password         string             `form:"password"`
	Strategy         model.SignInMethod `form:"strategy"`
	Token            string             `form:"token"`
}

type SignUpRequest struct {
	FirstName        string `form:"first_name"`
	LastName         string `form:"last_name"`
	Username         string `form:"username"`
	PhoneNumber      string `form:"phone_number"`
	PhoneCountryCode string `form:"phone_country_code"`
	Email            string `form:"email"`
	Password         string `form:"password"`
	InviteToken      string `form:"invite_token"`
}

type SocialCallbackResponse struct {
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
	OTP   string `form:"otp"`
}

type ResetPasswordRequest struct {
	Token    string `form:"token"`
	Password string `form:"password"`
}

type SetupAuthenticatorRequest struct {
	Email string `form:"email"`
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
