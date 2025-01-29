package model

import (
	"database/sql/driver"

	"gorm.io/datatypes"
)

type SignupAttemptStep string

const (
	SignupAttemptStepVerifyEmail SignupAttemptStep = "verify_email"
	SignupAttemptStepVerifyPhone SignupAttemptStep = "verify_phone"
)

func (s *SignupAttemptStep) Scan(value interface{}) error {
	*s = SignupAttemptStep(value.(string))
	return nil
}

func (s SignupAttemptStep) Value() (driver.Value, error) {
	return string(s), nil
}

type SignupAttemptStatus string

const (
	SignupAttemptStatusPending  SignupAttemptStatus = "pending"
	SignupAttemptStatusApproved SignupAttemptStatus = "complete"
)

func (s *SignupAttemptStatus) Scan(value interface{}) error {
	*s = SignupAttemptStatus(value.(string))
	return nil
}

func (s SignupAttemptStatus) Value() (driver.Value, error) {
	return string(s), nil
}

type SignupAttempt struct {
	Model
	SessionID      uint                                   `json:"session_id"`
	FirstName      string                                 `json:"first_name"`
	LastName       string                                 `json:"last_name"`
	Email          string                                 `json:"email"`
	Username       string                                 `json:"username"`
	PhoneNumber    string                                 `json:"phone_number"`
	Password       string                                 `json:"password"`
	RequiredFields datatypes.JSONSlice[string]            `json:"required_fields"`
	MissingFields  datatypes.JSONSlice[string]            `json:"missing_fields"`
	CurrentStep    SignupAttemptStep                      `json:"current_step"`
	RemainingSteps datatypes.JSONSlice[SignupAttemptStep] `json:"remaining_steps"`
}
