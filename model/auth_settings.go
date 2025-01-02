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
	SecondFactorEmailOTP      SecondFactor = "email_otp"
	SecondFactorPhoneOTP      SecondFactor = "phone_otp"
	SecondFactorWeb3Wallet    SecondFactor = "web3_wallet"
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
		return errors.New(fmt.Sprint("Failed to unmarshal JSONB value:", src))
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
	return "json"
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
		return errors.New(fmt.Sprint("Failed to unmarshal JSONB value:", src))
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
	return "json"
}

func (v *VerificationPolicy) GormDBDataType() string {
	return "jsonb"
}

type AuthFactorsEnabled struct {
	EmailPassword    bool `json:"email_password"`
	UsernamePassword bool `json:"username_password"`
	EmailOTP         bool `json:"email_otp"`
	PhoneOTP         bool `json:"phone_otp"`
	Web3Wallet       bool `json:"web3_wallet"`
	BackupCode       bool `json:"backup_code"`
	Authenticator    bool `json:"authenticator"`
}

func (a *AuthFactorsEnabled) Scan(src any) error {
	bytes, ok := src.([]byte)
	if !ok {
		return errors.New(fmt.Sprint("Failed to unmarshal JSONB value:", src))
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
	return "json"
}

func (a *AuthFactorsEnabled) GormDBDataType() string {
	return "jsonb"
}

type AuthSettings struct {
	Model
	EmailAddress           IndividualAuthSettings `json:"email_address"`
	PhoneNumber            IndividualAuthSettings `json:"phone_number"`
	Username               IndividualAuthSettings `json:"username"`
	FirstName              IndividualAuthSettings `json:"first_name"`
	LastName               IndividualAuthSettings `json:"last_name"`
	Password               IndividualAuthSettings `json:"password"`
	BackupCode             IndividualAuthSettings `json:"backup_code"`
	Web3Wallet             IndividualAuthSettings `json:"web3_wallet"`
	PasswordPolicy         IndividualAuthSettings `json:"password_policy"`
	AuthFactorsEnabled     AuthFactorsEnabled     `json:"auth_factors_enabled"`
	VerificationPolicy     VerificationPolicy     `json:"verification_policy"`
	SecondFactorPolicy     SecondFactorPolicy     `json:"second_factor_policy"`
	FirstFactor            FirstFactor            `json:"first_factor"`
	SecondFactor           SecondFactor           `json:"second_factor"`
	AlternateFirstFactors  []FirstFactor          `gorm:"type:text[]" json:"alternate_first_factors"`
	AlternateSecondFactors []SecondFactor         `gorm:"type:text[]" json:"alternate_second_factors"`
	DeploymentID           uint                   `json:"deployment_id"`
}
