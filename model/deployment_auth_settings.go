package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
)

type FirstFactor string

const (
	FirstFactorEmailPassword    FirstFactor = "email_password"
	FirstFactorUsernamePassword FirstFactor = "username_password"
	FirstFactorEmailOTP         FirstFactor = "email_otp"
	FirstFactorMagicLink        FirstFactor = "email_magic_link"
	FirstFactorPhoneOTP         FirstFactor = "phone_otp"
)

func (f *FirstFactor) Scan(value any) error {
	*f = FirstFactor(value.(string))
	return nil
}

func (f *FirstFactor) Value() (driver.Value, error) {
	return string(*f), nil
}

func (f FirstFactor) GormDataType() string {
	return "text"
}

func (f FirstFactor) GormDBDataType() string {
	return "text"
}

type SecondFactorPolicy string

const (
	SecondFactorPolicyNone     SecondFactorPolicy = "none"
	SecondFactorPolicyOptional SecondFactorPolicy = "optional"
	SecondFactorPolicyEnforced SecondFactorPolicy = "enforced"
)

func (s *SecondFactorPolicy) Scan(value any) error {
	*s = SecondFactorPolicy(value.(string))
	return nil
}

func (s *SecondFactorPolicy) Value() (driver.Value, error) {
	return string(*s), nil
}

type IndividualAuthSettings struct {
	Enabled  bool `json:"enabled"`
	Required bool `json:"required"`
}

func (i *IndividualAuthSettings) Scan(src any) error {
	bytes, ok := src.([]byte)
	if !ok {
		return errors.New(
			fmt.Sprint("Failed to unmarshal JSONB value:", src),
		)
	}

	result := IndividualAuthSettings{}
	err := json.Unmarshal(bytes, &result)
	*i = IndividualAuthSettings(result)
	return err
}

func (i *IndividualAuthSettings) Value() (driver.Value, error) {
	return json.Marshal(i)
}

func (i *IndividualAuthSettings) GormDataType() string {
	return "jsonb"
}

func (i *IndividualAuthSettings) GormDBDataType() string {
	return "jsonb"
}

type VerificationPolicy struct {
	PhoneNumber bool `json:"phone_number"`
	Email       bool `json:"email"`
}

func (v *VerificationPolicy) Scan(src any) error {
	bytes, ok := src.([]byte)
	if !ok {
		return errors.New(
			fmt.Sprint("Failed to unmarshal JSONB value:", src),
		)
	}

	result := VerificationPolicy{}
	err := json.Unmarshal(bytes, &result)
	*v = VerificationPolicy(result)
	return err
}

func (v *VerificationPolicy) Value() (driver.Value, error) {
	return json.Marshal(v)
}

func (v *VerificationPolicy) GormDataType() string {
	return "jsonb"
}

func (v *VerificationPolicy) GormDBDataType() string {
	return "jsonb"
}

type AuthFactorsEnabled struct {
	EmailPassword    bool `json:"email_password"`
	UsernamePassword bool `json:"username_password"`
	EmailOTP         bool `json:"email_otp"`
	EmailMagicLink   bool `json:"email_magic_link"`
	PhoneOTP         bool `json:"phone_otp"`
	Web3Wallet       bool `json:"web3_wallet"`
	BackupCode       bool `json:"backup_code"`
	Authenticator    bool `json:"authenticator"`
}

func (a *AuthFactorsEnabled) Scan(src any) error {
	bytes, ok := src.([]byte)
	if !ok {
		return errors.New(
			fmt.Sprint("Failed to unmarshal JSONB value:", src),
		)
	}

	result := AuthFactorsEnabled{}
	err := json.Unmarshal(bytes, &result)
	*a = AuthFactorsEnabled(result)
	return err
}

func (a *AuthFactorsEnabled) Value() (driver.Value, error) {
	return json.Marshal(a)
}

func (a *AuthFactorsEnabled) GormDataType() string {
	return "jsonb"
}

func (a *AuthFactorsEnabled) GormDBDataType() string {
	return "jsonb"
}

type EmailSettings struct {
	Enabled                      bool `json:"enabled"`
	Required                     bool `json:"required"`
	VerifySignup                 bool `json:"verify_signup,omitempty"`
	OtpVerificationAllowed       bool `json:"otp_verification_allowed,omitempty"`
	MagicLinkVerificationAllowed bool `json:"magic_link_verification_allowed,omitempty"`
}

func (e *EmailSettings) Scan(src any) error {
	bytes, ok := src.([]byte)
	if !ok {
		return errors.New(fmt.Sprint("Failed to unmarshal JSONB value:", src))
	}
	result := EmailSettings{}
	err := json.Unmarshal(bytes, &result)
	*e = result
	return err
}

func (e *EmailSettings) Value() (driver.Value, error) {
	return json.Marshal(e)
}

func (e *EmailSettings) GormDataType() string {
	return "jsonb"
}

func (e *EmailSettings) GormDBDataType() string {
	return "jsonb"
}

type PhoneSettings struct {
	Enabled                     bool `json:"enabled"`
	Required                    bool `json:"required"`
	VerifySignup                bool `json:"verify_signup,omitempty"`
	SmsVerificationAllowed      bool `json:"sms_verification_allowed,omitempty"`
	WhatsappVerificationAllowed bool `json:"whatsapp_verification_allowed,omitempty"`
}

func (p *PhoneSettings) Scan(src any) error {
	bytes, ok := src.([]byte)
	if !ok {
		return errors.New(fmt.Sprint("Failed to unmarshal JSONB value:", src))
	}
	result := PhoneSettings{}
	err := json.Unmarshal(bytes, &result)
	*p = result
	return err
}

func (p *PhoneSettings) Value() (driver.Value, error) {
	return json.Marshal(p)
}

func (p *PhoneSettings) GormDataType() string {
	return "jsonb"
}

func (p *PhoneSettings) GormDBDataType() string {
	return "jsonb"
}

type UsernameSettings struct {
	Enabled   bool   `json:"enabled"`
	Required  bool   `json:"required"`
	MinLength uint64 `json:"min_length,omitempty"`
	MaxLength uint64 `json:"max_length,omitempty"`
}

func (u *UsernameSettings) Scan(src any) error {
	bytes, ok := src.([]byte)
	if !ok {
		return errors.New(fmt.Sprint("Failed to unmarshal JSONB value:", src))
	}
	result := UsernameSettings{}
	err := json.Unmarshal(bytes, &result)
	*u = result
	return err
}

func (u *UsernameSettings) Value() (driver.Value, error) {
	return json.Marshal(u)
}

func (u *UsernameSettings) GormDataType() string {
	return "jsonb"
}

func (u *UsernameSettings) GormDBDataType() string {
	return "jsonb"
}

type PasswordSettings struct {
	Enabled            bool   `json:"enabled"`
	MinLength          uint64 `json:"min_length,omitempty"`
	RequireLowercase   bool   `json:"require_lowercase,omitempty"`
	RequireUppercase   bool   `json:"require_uppercase,omitempty"`
	RequireNumber      bool   `json:"require_number,omitempty"`
	RequireSpecialChar bool   `json:"require_special,omitempty"`
}

func (p *PasswordSettings) Scan(src any) error {
	bytes, ok := src.([]byte)
	if !ok {
		return errors.New(fmt.Sprint("Failed to unmarshal JSONB value:", src))
	}
	result := PasswordSettings{}
	err := json.Unmarshal(bytes, &result)
	*p = result
	return err
}

func (p *PasswordSettings) Value() (driver.Value, error) {
	return json.Marshal(p)
}

func (p *PasswordSettings) GormDataType() string {
	return "jsonb"
}

func (p *PasswordSettings) GormDBDataType() string {
	return "jsonb"
}

type EmailLinkSettings struct {
	Enabled           bool `json:"enabled"`
	RequireSameDevice bool `json:"require_same_device"`
}

func (e *EmailLinkSettings) Scan(src any) error {
	bytes, ok := src.([]byte)
	if !ok {
		if src == nil {
			return nil
		}
		return errors.New(fmt.Sprint("Failed to unmarshal JSONB value:", src))
	}
	result := EmailLinkSettings{}
	err := json.Unmarshal(bytes, &result)
	*e = result
	return err
}

func (e *EmailLinkSettings) Value() (driver.Value, error) {
	return json.Marshal(e)
}

func (e *EmailLinkSettings) GormDataType() string {
	return "jsonb"
}

func (e *EmailLinkSettings) GormDBDataType() string {
	return "jsonb"
}

type PasskeySettings struct {
	Enabled       bool `json:"enabled"`
	AllowAutofill bool `json:"allow_autofill"`
}

func (p *PasskeySettings) Scan(src any) error {
	bytes, ok := src.([]byte)
	if !ok {
		if src == nil {
			return nil
		}
		return errors.New(fmt.Sprint("Failed to unmarshal JSONB value:", src))
	}
	result := PasskeySettings{}
	err := json.Unmarshal(bytes, &result)
	*p = result
	return err
}

func (p *PasskeySettings) Value() (driver.Value, error) {
	return json.Marshal(p)
}

func (p *PasskeySettings) GormDataType() string {
	return "jsonb"
}

func (p *PasskeySettings) GormDBDataType() string {
	return "jsonb"
}

type MultiSessionSupport struct {
	Enabled               bool   `json:"enabled"`
	MaxAccountsPerSession uint64 `json:"max_accounts_per_session"`
	MaxSessionsPerAccount uint64 `json:"max_sessions_per_account"`
}

func (m *MultiSessionSupport) Scan(src any) error {
	bytes, ok := src.([]byte)
	if !ok {
		return errors.New(fmt.Sprint("Failed to unmarshal JSONB value:", src))
	}
	result := MultiSessionSupport{}
	err := json.Unmarshal(bytes, &result)
	*m = result
	return err
}

func (m *MultiSessionSupport) Value() (driver.Value, error) {
	return json.Marshal(m)
}

func (m *MultiSessionSupport) GormDataType() string {
	return "jsonb"
}

func (m *MultiSessionSupport) GormDBDataType() string {
	return "jsonb"
}

type DeploymentAuthSettings struct {
	Model
	EmailAddress           EmailSettings          `json:"email_address"            gorm:"not null"`
	PhoneNumber            PhoneSettings          `json:"phone_number"             gorm:"not null"`
	Username               UsernameSettings       `json:"username"                 gorm:"not null"`
	FirstName              IndividualAuthSettings `json:"first_name"               gorm:"not null"`
	LastName               IndividualAuthSettings `json:"last_name"                gorm:"not null"`
	Password               PasswordSettings       `json:"password"                 gorm:"not null"`
	MagicLink              *EmailLinkSettings     `json:"magic_link"               gorm:"not null"`
	Passkey                *PasskeySettings       `json:"passkey"                  gorm:"not null"`
	AuthFactorsEnabled     AuthFactorsEnabled     `json:"auth_factors_enabled"     gorm:"not null"`
	VerificationPolicy     VerificationPolicy     `json:"verification_policy"      gorm:"not null"`
	SecondFactorPolicy     SecondFactorPolicy     `json:"second_factor_policy"     gorm:"not null"`
	FirstFactor            FirstFactor            `json:"first_factor"             gorm:"not null"`
	SessionTokenLifetime   uint64                 `json:"session_token_lifetime"   gorm:"not null"`
	SessionValidityPeriod  uint64                 `json:"session_validity_period"  gorm:"not null"`
	SessionInactiveTimeout uint64                 `json:"session_inactive_timeout" gorm:"not null"`
	MultiSessionSupport    MultiSessionSupport    `json:"multi_session_support"    gorm:"not null"`
	DeploymentID           uint64                 `json:"deployment_id"            gorm:"not null;index"`
}
