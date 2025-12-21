package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/godruoyi/go-snowflake"
	"gorm.io/datatypes"
)

type ProfileCompletionData struct {
	FirstName        string `json:"first_name,omitempty"`
	LastName         string `json:"last_name,omitempty"`
	Username         string `json:"username,omitempty"`
	Email            string `json:"email,omitempty"`
	PhoneNumber      string `json:"phone_number,omitempty"`
	PhoneCountryCode string `json:"phone_country_code,omitempty"`
}

type SignInMethod string

const (
	SignInMethodPlainEmail    SignInMethod = "plain_email"
	SignInMethodPlainUsername SignInMethod = "plain_username"
	SignInMethodPhoneOTP      SignInMethod = "phone_otp"
	SignInMethodMagicLink     SignInMethod = "magic_link"
	SignInMethodEmailOTP      SignInMethod = "email_otp"
	SignInMethodSSO           SignInMethod = "sso"            // OAuth2 social login
	SignInMethodEnterpriseSso SignInMethod = "enterprise_sso" // SAML/OIDC enterprise SSO
	SignInMethodPasskey       SignInMethod = "passkey"
	SignInMethodImpersonation SignInMethod = "impersonation"
)

func (s *SignInMethod) Scan(value any) error {
	*s = SignInMethod(value.(string))
	return nil
}

func (s SignInMethod) Value() (driver.Value, error) {
	return string(s), nil
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Scan(src any) error {
	bytes, ok := src.([]byte)
	if !ok {
		return errors.New(
			fmt.Sprint("Failed to unmarshal JSONB value:", src),
		)
	}

	result := Error{}
	err := json.Unmarshal(bytes, &result)
	*e = Error(result)
	return err
}

func (e *Error) Value() (driver.Value, error) {
	return json.Marshal(e)
}

func (e *Error) GormDataType() string {
	return "jsonb"
}

func (e *Error) GormDBDataType() string {
	return "jsonb"
}

type SignInAttempt struct {
	Model
	UserID                             *uint64                                `json:"-"`
	IdentifierID                       *uint64                                `json:"-"`
	SessionID                          uint64                                 `json:"session_id"                            gorm:"not null"`
	Method                             SignInMethod                           `json:"method"                                gorm:"not null"`
	SSOProvider                        SocialConnectionProvider               `json:"sso_provider"`
	EnterpriseConnectionID             *uint64                                `json:"enterprise_connection_id"`
	SamlRequestID                      *string                                `json:"-"`
	OIDCState                          *string                                `json:"-"                                     gorm:"column:oidc_state"` // For OIDC CSRF protection
	ExpiresAt                          time.Time                              `json:"expires_at"                            gorm:"not null"`
	CurrentStep                        SignInAttemptStep                      `json:"current_step"                          gorm:"not null"`
	RemainingSteps                     datatypes.JSONSlice[SignInAttemptStep] `json:"remaining_steps"                       gorm:"not null"`
	Completed                          bool                                   `json:"completed"                             gorm:"not null"`
	Errored                            bool                                   `json:"errored"                               gorm:"not null"`
	Errors                             datatypes.JSONSlice[Error]             `json:"errors"`
	RequiresCompletion                 bool                                   `json:"requires_completion"`
	MissingFields                      datatypes.JSONSlice[string]            `json:"missing_fields"`
	RequiredFields                     datatypes.JSONSlice[string]            `json:"required_fields"`
	FirstMethodAuthenticated           bool                                   `json:"first_method_authenticated"            gorm:"not null;default:false"`
	SecondMethodAuthenticated          bool                                   `json:"second_method_authenticated"           gorm:"not null;default:false"`
	SecondMethodAuthenticationRequired bool                                   `json:"second_method_authentication_required" gorm:"not null;default:false"`
	Available2FAMethods                datatypes.JSONSlice[string]            `json:"available_2fa_methods"                 gorm:"column:available_2fa_methods"`
	ProfileCompletionData              *ProfileCompletionData                 `json:"profile_completion_data,omitempty"     gorm:"type:jsonb"`
}

func NewSignInAttempt(method SignInMethod) *SignInAttempt {
	return &SignInAttempt{
		Model: Model{
			ID: snowflake.ID(),
		},
		Method:    method,
		ExpiresAt: time.Now().UTC().Add(time.Minute * 10),
	}
}

type Test struct {
	Model
}
