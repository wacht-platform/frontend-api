package handler

import (
	"errors"
	"fmt"
	"log"

	"github.com/gofiber/fiber/v2"
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
	ErrCodeUnauthorized                 = "UNAUTHORIZED"
	ErrCodeProviderNotConfigured        = "PROVIDER_NOT_CONFIGURED"
	ErrCodeSignupRestricted             = "SIGNUP_RESTRICTED"
	ErrCodeSignupWaitlistOnly           = "SIGNUP_WAITLIST_ONLY"
	ErrCodeEmailNotAllowed              = "EMAIL_NOT_ALLOWED"
	ErrCodeEmailBlocked                 = "EMAIL_BLOCKED"
	ErrCodeDisposableEmail              = "DISPOSABLE_EMAIL_BLOCKED"
	ErrCodeCountryRestricted            = "COUNTRY_RESTRICTED"
	ErrCodeVoipNumberBlocked            = "VOIP_NUMBER_BLOCKED"
	ErrCodeBannedKeyword                = "BANNED_KEYWORD"
	ErrCodeNoAlternativeAuthMethod      = "NO_ALTERNATIVE_AUTH_METHOD"
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
		Message: "Invalid credentials. Please try again.",
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
	ErrUnauthorized = Error{
		Code:    ErrCodeUnauthorized,
		Message: "Unauthorized.",
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
	ErrProviderNotConfigured = Error{
		Code:    ErrCodeProviderNotConfigured,
		Message: "OAuth provider is not configured for this deployment.",
	}
	ErrSignupRestricted = Error{
		Code:    ErrCodeSignupRestricted,
		Message: "Signup is currently restricted for this deployment.",
	}
	ErrSignupWaitlistOnly = Error{
		Code:    ErrCodeSignupWaitlistOnly,
		Message: "Signup is currently in waitlist mode. Please join the waitlist instead.",
	}
	ErrEmailNotAllowed = Error{
		Code:    ErrCodeEmailNotAllowed,
		Message: "This email address is not allowed.",
	}
	ErrEmailBlocked = Error{
		Code:    ErrCodeEmailBlocked,
		Message: "This email address is blocked.",
	}
	ErrDisposableEmail = Error{
		Code:    ErrCodeDisposableEmail,
		Message: "Disposable email addresses are not allowed.",
	}
	ErrCountryRestricted = Error{
		Code:    ErrCodeCountryRestricted,
		Message: "Signup is not allowed from your country.",
	}
	ErrVoipNumberBlocked = Error{
		Code:    ErrCodeVoipNumberBlocked,
		Message: "VOIP phone numbers are not allowed.",
	}
	ErrBannedKeyword = Error{
		Code:    ErrCodeBannedKeyword,
		Message: "Your input contains restricted content.",
	}
	ErrNoAlternativeAuthMethod = Error{
		Code:    ErrCodeNoAlternativeAuthMethod,
		Message: "Cannot remove password. You must have at least one alternative authentication method configured (verified email for OTP/magic link, social connection, or passkey).",
	}
	ErrSocialAccountAlreadyConnected = Error{
		Code:    "SOCIAL_ACCOUNT_ALREADY_CONNECTED",
		Message: "This social account is already connected to another user.",
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

func DefaultErrorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError

	var e *fiber.Error
	if errors.As(err, &e) {
		code = e.Code
	}

	log.Println(err.Error())

	if code == 404 {
		return SendNotFound(c, nil, "Resource does not exist")
	}

	return SendResponse[any](
		c,
		code,
		nil,
		"Something went wrong. Please try again later.",
		[]Error{},
	)
}
