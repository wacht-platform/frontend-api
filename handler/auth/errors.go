package auth

import (
	"fmt"
)

type AuthError struct {
	Code    string
	Message string
}

func (e AuthError) Error() string {
	return e.Message
}

const (
	ErrCodeUserNotFound       = "USER_NOT_FOUND"
	ErrCodeUserDisabled       = "USER_DISABLED"
	ErrCodeInvalidCredentials = "INVALID_CREDENTIALS"
	ErrCodeEmailExists        = "EMAIL_EXISTS"
	ErrCodeProviderRequired   = "PROVIDER_REQUIRED"
	ErrCodeCodeRequired       = "CODE_REQUIRED"
	ErrCodeInvalidState       = "INVALID_STATE"
	ErrCodeInvalidCode        = "INVALID_CODE"
	ErrCodeRequiredField      = "REQUIRED_FIELD"
)

var (
	ErrUserNotFound       = AuthError{Code: ErrCodeUserNotFound, Message: "user not found"}
	ErrUserDisabled       = AuthError{Code: ErrCodeUserDisabled, Message: "user is disabled"}
	ErrInvalidCredentials = AuthError{Code: ErrCodeInvalidCredentials, Message: "invalid credentials"}
	ErrEmailExists        = AuthError{Code: ErrCodeEmailExists, Message: "email address already exists"}
	ErrProviderRequired   = AuthError{Code: ErrCodeProviderRequired, Message: "provider is required"}
	ErrCodeRequired       = AuthError{Code: ErrCodeCodeRequired, Message: "code is required"}
	ErrInvalidState       = AuthError{Code: ErrCodeInvalidState, Message: "invalid state"}
	ErrInvalidCode        = AuthError{Code: ErrCodeInvalidCode, Message: "invalid code"}
)

// ErrRequiredField creates an error for a required field
func ErrRequiredField(field string) error {
	return AuthError{
		Code:    ErrCodeRequiredField,
		Message: fmt.Sprintf("%s is required", field),
	}
}

// Is implements the errors.Is interface for AuthError
func (e AuthError) Is(target error) bool {
	t, ok := target.(AuthError)
	if !ok {
		return false
	}
	return e.Code == t.Code
}
