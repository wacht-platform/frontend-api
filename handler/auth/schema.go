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
