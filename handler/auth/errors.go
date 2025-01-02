package auth

import (
	"fmt"
)

// AuthError represents an authentication error
type AuthError struct {
	Code    string
	Message string
}

func (e AuthError) Error() string {
	return e.Message
}

// Error codes
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
	// ErrUserNotFound is returned when a user cannot be found
	ErrUserNotFound = AuthError{Code: ErrCodeUserNotFound, Message: "user not found"}
	// ErrUserDisabled is returned when a user account is disabled
	ErrUserDisabled = AuthError{Code: ErrCodeUserDisabled, Message: "user is disabled"}
	// ErrInvalidCredentials is returned when provided credentials are invalid
	ErrInvalidCredentials = AuthError{Code: ErrCodeInvalidCredentials, Message: "invalid credentials"}
	// ErrEmailExists is returned when trying to create a user with an existing email
	ErrEmailExists = AuthError{Code: ErrCodeEmailExists, Message: "email address already exists"}
	// ErrProviderRequired is returned when SSO provider is not specified
	ErrProviderRequired = AuthError{Code: ErrCodeProviderRequired, Message: "provider is required"}
	// ErrCodeRequired is returned when OAuth code is missing
	ErrCodeRequired = AuthError{Code: ErrCodeCodeRequired, Message: "code is required"}
	// ErrInvalidState is returned when OAuth state is invalid
	ErrInvalidState = AuthError{Code: ErrCodeInvalidState, Message: "invalid state"}
	// ErrInvalidCode is returned when OAuth code is invalid
	ErrInvalidCode = AuthError{Code: ErrCodeInvalidCode, Message: "invalid code"}
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
