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

type SignInMethod string

const (
	SignInMethodPlainEmail    SignInMethod = "plain_email"
	SignInMethodPlainUsername SignInMethod = "plain_username"
	SignInMethodPhoneOTP      SignInMethod = "phone_otp"
	SignInMethodMagicLink     SignInMethod = "magic_link"
	SignInMethodEmailOTP      SignInMethod = "email_otp"
	SignInMethodSSO           SignInMethod = "sso"
	Passkey                   SignInMethod = "passkey"
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
	UserID         uint                                   `json:"-"`
	IdentifierID   uint                                   `json:"-"`
	SessionID      uint                                   `json:"session_id"      gorm:"not null"`
	Method         SignInMethod                           `json:"method"          gorm:"not null"`
	SSOProvider    SocialConnectionProvider               `json:"sso_provider"`
	ExpiresAt      time.Time                              `json:"expires_at"      gorm:"not null"`
	CurrentStep    SignInAttemptStep                      `json:"current_step"    gorm:"not null"`
	RemainingSteps datatypes.JSONSlice[SignInAttemptStep] `json:"remaining_steps" gorm:"not null"`
	Completed      bool                                   `json:"completed"       gorm:"not null"`
	Errored        bool                                   `json:"errored"         gorm:"not null"`
	Errors         datatypes.JSONSlice[Error]             `json:"errors"`
}

func NewSignInAttempt(method SignInMethod) *SignInAttempt {
	return &SignInAttempt{
		Model: Model{
			ID: uint(snowflake.ID()),
		},
		Method:    method,
		ExpiresAt: time.Now().Add(time.Minute * 10),
	}
}
