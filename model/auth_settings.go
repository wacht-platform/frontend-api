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

type SecondFactor string

const (
	SecondFactorNone          SecondFactor = "none"
	SecondFactorPhoneOTP      SecondFactor = "phone_otp"
	SecondFactorBackupCode    SecondFactor = "backup_code"
	SecondFactorAuthenticator SecondFactor = "authenticator"
)

func (s *SecondFactor) Scan(value any) error {
	*s = SecondFactor(value.([]byte))
	return nil
}

func (s *SecondFactor) Value() (driver.Value, error) {
	return string(*s), nil
}

func (s SecondFactor) GormDataType() string {
	return "text"
}

func (s SecondFactor) GormDBDataType() string {
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
	Enabled   bool  `json:"enabled"`
	Required  bool  `json:"required"`
	MinLength uint8 `json:"min_length,omitempty"`
	MaxLength uint8 `json:"max_length,omitempty"`
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
	Enabled            bool  `json:"enabled"`
	MinLength          uint8 `json:"min_length,omitempty"`
	RequireLowercase   bool  `json:"require_lowercase,omitempty"`
	RequireUppercase   bool  `json:"require_uppercase,omitempty"`
	RequireNumber      bool  `json:"require_number,omitempty"`
	RequireSpecialChar bool  `json:"require_special,omitempty"`
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

type DeploymentAuthSettings struct {
	Model
	EmailAddress           EmailSettings          `json:"email_address"`
	PhoneNumber            PhoneSettings          `json:"phone_number"`
	Username               UsernameSettings       `json:"username"`
	FirstName              IndividualAuthSettings `json:"first_name"`
	LastName               IndividualAuthSettings `json:"last_name"`
	Password               PasswordSettings       `json:"password"`
	MagicLink              *EmailLinkSettings     `json:"magic_link"`
	Passkey                *PasskeySettings       `json:"passkey"`
	AuthFactorsEnabled     AuthFactorsEnabled     `json:"auth_factors_enabled"`
	VerificationPolicy     VerificationPolicy     `json:"verification_policy"`
	SecondFactorPolicy     SecondFactorPolicy     `json:"second_factor_policy"`
	FirstFactor            FirstFactor            `json:"first_factor"`
	SecondFactor           SecondFactor           `json:"second_factor"`
	AlternateFirstFactors  []FirstFactor          `json:"alternate_first_factors"  gorm:"type:text[]"`
	AlternateSecondFactors []SecondFactor         `json:"alternate_second_factors" gorm:"type:text[]"`
	DeploymentID           uint                   `json:"deployment_id"`
}
