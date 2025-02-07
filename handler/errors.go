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
	ErrCodeUsernameExists               = "USERNAME_EXISTS"
	ErrCodePhoneNumberExists            = "PHONE_NUMBER_EXISTS"
	ErrCodeProviderRequired             = "PROVIDER_REQUIRED"
	ErrCodeCodeRequired                 = "CODE_REQUIRED"
	ErrCodeVerificationStrategyRequired = "VERIFICATION_STRATEGY_REQUIRED"
	ErrCodeInvalidState                 = "INVALID_STATE"
	ErrCodeInvalidCode                  = "INVALID_CODE"
	ErrCodeRequiredField                = "REQUIRED_FIELD"
	ErrCodeBadRequestBody               = "BAD_REQUEST_BODY"
	ErrorCodeInternal                   = "INTERNAL"
	ErrorCodeBadSignInAttempt           = "BAD_SIGN_IN_ATTEMPT"
	ErrorCodeUserAlreadySignedIn        = "USER_ALREADY_SIGNED_IN"
)

var (
	ErrUserNotFound = Error{
		Code:    ErrCodeUserNotFound,
		Message: "User not found.",
	}
	ErrUserDisabled = Error{
		Code:    ErrCodeUserDisabled,
		Message: "User account is disabled.",
	}
	ErrInvalidCredentials = Error{
		Code:    ErrCodeInvalidCredentials,
		Message: "Incorrect password. Please try again.",
	}
	ErrEmailExists = Error{
		Code:    ErrCodeEmailExists,
		Message: "This email address is already in use.",
	}
	ErrUsernameExists = Error{
		Code:    ErrCodeUsernameExists,
		Message: "This username is already taken.",
	}
	ErrPhoneNumberExists = Error{
		Code:    ErrCodePhoneNumberExists,
		Message: "This phone number is already associated with an account.",
	}
	ErrProviderRequired = Error{
		Code:    ErrCodeProviderRequired,
		Message: "Authentication provider is required.",
	}
	ErrCodeRequired = Error{
		Code:    ErrCodeCodeRequired,
		Message: "A verification code is required.",
	}
	ErrInvalidState = Error{
		Code:    ErrCodeInvalidState,
		Message: "Invalid request state.",
	}
	ErrInvalidCode = Error{
		Code:    ErrCodeInvalidCode,
		Message: "The provided code is invalid.",
	}
	ErrBadRequestBody = Error{
		Code:    ErrCodeBadRequestBody,
		Message: "Unable to process request body. Please check the format.",
	}
	ErrInternal = Error{
		Code:    ErrorCodeInternal,
		Message: "An internal server error occurred. Please try again later.",
	}
	ErrInvalidSignInAttempt = Error{
		Code:    ErrorCodeBadSignInAttempt,
		Message: "Unsuccessful sign-in attempt. Please verify your credentials.",
	}
	ErrVerificationStrategyRequired = Error{
		Code:    ErrCodeVerificationStrategyRequired,
		Message: "A verification strategy must be specified.",
	}
	ErrUserAlreadySignedIn = Error{
		Code:    ErrorCodeUserAlreadySignedIn,
		Message: "You are already signed in.",
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
