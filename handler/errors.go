package handler

import (
	"fmt"
)

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e Error) Error() string {
	return e.Message
}

const (
	ErrCodeUserNotFound                 = "USER_NOT_FOUND"
	ErrCodeUserDisabled                 = "USER_DISABLED"
	ErrCodeInvalidCredentials           = "INVALID_CREDENTIALS"
	ErrCodeEmailExists                  = "EMAIL_EXISTS"
	ErrCodeProviderRequired             = "PROVIDER_REQUIRED"
	ErrCodeCodeRequired                 = "CODE_REQUIRED"
	ErrCodeVerificationStrategyRequired = "VERIFICATION_STRATEGY_REQUIRED"
	ErrCodeInvalidState                 = "INVALID_STATE"
	ErrCodeInvalidCode                  = "INVALID_CODE"
	ErrCodeRequiredField                = "REQUIRED_FIELD"
	ErrCodeBadRequestBody               = "BAD_REQUEST_BODY"
	ErrorCodeInternal                   = "INTERNAL"
	ErrorCodeBadSignInAttempt           = "BAD_SIGN_IN_ATTEMPT"
)

var (
	ErrUserNotFound = Error{
		Code:    ErrCodeUserNotFound,
		Message: "user not found",
	}
	ErrUserDisabled = Error{
		Code:    ErrCodeUserDisabled,
		Message: "user is disabled",
	}
	ErrInvalidCredentials = Error{
		Code:    ErrCodeInvalidCredentials,
		Message: "invalid credentials",
	}
	ErrEmailExists = Error{
		Code:    ErrCodeEmailExists,
		Message: "email address already exists",
	}
	ErrProviderRequired = Error{
		Code:    ErrCodeProviderRequired,
		Message: "provider is required",
	}
	ErrCodeRequired = Error{
		Code:    ErrCodeCodeRequired,
		Message: "code is required",
	}
	ErrInvalidState = Error{
		Code:    ErrCodeInvalidState,
		Message: "invalid state",
	}
	ErrInvalidCode = Error{
		Code:    ErrCodeInvalidCode,
		Message: "invalid code",
	}
	ErrBadRequestBody = Error{
		Code:    ErrCodeBadRequestBody,
		Message: "cannot parse request body",
	}
	ErrInternal = Error{
		Code:    ErrorCodeInternal,
		Message: "internal server error",
	}
	ErrInvalidSignInAttempt = Error{
		Code:    ErrorCodeBadSignInAttempt,
		Message: "bad sign in attempt",
	}
	ErrVerificationStrategyRequired = Error{
		Code:    ErrCodeVerificationStrategyRequired,
		Message: "verification strategy is required",
	}
)

func ErrRequiredField(field string) error {
	return Error{
		Code:    ErrCodeRequiredField,
		Message: fmt.Sprintf("%s is required", field),
	}
}

func (e Error) Is(target error) bool {
	t, ok := target.(Error)
	if !ok {
		return false
	}
	return e.Code == t.Code
}
