package auth

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"slices"

	"github.com/godruoyi/go-snowflake"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/utils"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pquerna/otp/totp"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type Handler struct {
	service *AuthService
}

func NewHandler() *Handler {
	return &Handler{
		service: NewAuthService(),
	}
}

func (h *Handler) SignIn(c *fiber.Ctx) error {
	b, validation := handler.Validate[SignInRequest](c)

	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	d := handler.GetDeployment(c)
	session := handler.GetSession(c)

	if b.Email != "" {
		b.Email = strings.TrimSpace(b.Email)
		b.Email = strings.ToLower(b.Email)
	}

	switch b.Strategy {
	case model.SignInMethodEmailOTP:
		return h.handleOTPSignIn(c, *b, session, model.SignInMethodEmailOTP)
	case model.SignInMethodPhoneOTP:
		return h.handleOTPSignIn(c, *b, session, model.SignInMethodPhoneOTP)
	case model.SignInMethodMagicLink:
		return h.handleMagicLinkSignIn(c, *b, d, session)
	case model.SignInMethodPlainUsername:
		return h.handleUsernameSignIn(c, *b, d, session)
	case model.SignInMethodPlainEmail:
		return h.handleEmailPasswordSignIn(c, *b, d, session)
	case model.SignInMethodImpersonation:
		return h.handleImpersonationSignIn(c, *b, d, session)
	default:
		return handler.SendBadRequest(c, nil, "Invalid or missing strategy")
	}
}

func (h *Handler) handleUsernameSignIn(
	c *fiber.Ctx,
	b SignInRequest,
	d model.Deployment,
	session *model.Session,
) error {
	blocked, _ := utils.CheckRateLimit(b.Username)
	if blocked {
		return handler.SendForbidden(
			c,
			nil,
			"Too many failed attempts. Please try again later.",
			handler.ErrTooManyRequests,
		)
	}

	user, err := h.service.FindUserByUsername(b.Username, d.ID)
	if err != nil {
		if err == handler.ErrUserNotFound {
			_ = utils.IncrementRateLimit(b.Username)
			return handler.SendUnauthorized(c, nil, "Invalid credentials", handler.ErrInvalidCredentials)
		}
		return handler.SendInternalServerError(
			c,
			err,
			"Something went wrong",
		)
	}

	for _, signin := range session.Signins {
		if signin.UserID != nil && *signin.UserID == user.ID {
			return handler.SendBadRequest(
				c,
				nil,
				"User already signed in",
				handler.ErrUserAlreadySignedIn,
			)
		}
	}

	if err = h.service.ValidateUsernameUserStatus(user); err != nil {
		return handler.SendForbidden(
			c,
			nil,
			err.Error(),
			handler.ErrUserDisabled,
		)
	}

	missingFields := h.service.CheckMissingRequiredFields(user, d.AuthSettings)
	requiresCompletion := len(missingFields) > 0

	authenticated := false

	if b.Password != "" {
		match, err := h.service.VerifyPassword(
			user.Password,
			b.Password,
		)
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error comparing password")
		}

		if !match {
			_ = utils.IncrementRateLimit(b.Username)
			return handler.SendUnauthorized(c, nil, "Invalid credentials", handler.ErrInvalidCredentials)
		}
		authenticated = true
	}

	if !authenticated && b.Password != "" {
		return handler.SendUnauthorized(
			c,
			nil,
			"Invalid credentials",
			handler.ErrInvalidCredentials,
		)
	}

	if authenticated {
		_ = utils.ClearRateLimit(b.Username)
	}

	secondFactorEnforced := user.SecondFactorPolicy == model.SecondFactorPolicyEnforced

	var steps []model.SignInAttemptStep

	if secondFactorEnforced {
		steps = append(steps, model.SignInAttemptStepVerifySecondFactor)
	}

	if requiresCompletion {
		steps = append(steps, model.SignInAttemptStepCompleteProfile)
	}

	completed := len(steps) == 0 && authenticated

	attempt := h.service.CreateSignInAttempt(
		&user.ID,
		nil,
		session.ID,
		model.SignInMethodPlainUsername,
		steps,
		completed,
		&d,
	)

	attempt.FirstMethodAuthenticated = authenticated

	if requiresCompletion {
		attempt.RequiresCompletion = true
		attempt.MissingFields = datatypes.NewJSONSlice(missingFields)
		requiredFields := h.service.GetRequiredFields(d.AuthSettings)
		attempt.RequiredFields = datatypes.NewJSONSlice(requiredFields)
		completed = false
	}

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(attempt).Error; err != nil {
			return err
		}

		if completed {
			if err := h.service.ValidateIPCountryRestrictions(c, d.Restrictions); err != nil {
				return err
			}

			signIn := h.service.CreateSignin(user.ID, session.ID, c, d.AuthSettings.SessionValidityPeriod)
			if err := tx.Create(signIn).Error; err != nil {
				return err
			}

			if err := tx.Model(&model.Session{}).Where("id = ?", session.ID).Update("active_signin_id", signIn.ID).Error; err != nil {
				return err
			}

			if user.PrimaryEmailAddressID != nil {
				for _, email := range user.UserEmailAddresses {
					if email.ID == *user.PrimaryEmailAddressID {
						_ = h.service.nats.SendSignInNotificationEmail(d.ID, user.ID, signIn.ID, email.EmailAddress)
						break
					}
				}
			}

			utils.PublishSignInEvent(d.ID, user, string(b.Strategy), &user.Username, c)
		}

		return nil
	})

	if err == nil && completed {
		h.service.TrackMAU(d.ID, user.ID)
	}

	if err != nil &&
		err.(*pgconn.PgError).ConstraintName == "idx_session_user_id" {
		return handler.SendBadRequest(
			c,
			nil,
			"User already signed in",
			handler.ErrUserAlreadySignedIn,
		)
	}

	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Something went wrong",
		)
	}

	session.SigninAttempts = append(session.SigninAttempts, *attempt)
	handler.RemoveSessionFromCacheAndLocals(c, session.ID)
	return handler.SendSuccess(c, session)
}

func (h *Handler) handleEmailPasswordSignIn(
	c *fiber.Ctx,
	b SignInRequest,
	d model.Deployment,
	session *model.Session,
) error {
	blocked, _ := utils.CheckRateLimit(b.Email)
	if blocked {
		return handler.SendForbidden(
			c,
			nil,
			"Too many failed attempts. Please try again later.",
			handler.ErrTooManyRequests,
		)
	}

	email, err := h.service.FindUserByEmail(b.Email, d.ID)
	if err != nil {
		if err == handler.ErrUserNotFound {
			_ = utils.IncrementRateLimit(b.Email)
			return handler.SendUnauthorized(c, nil, "Invalid credentials", handler.ErrInvalidCredentials)
		}
		return handler.SendInternalServerError(
			c,
			err,
			"Something went wrong",
		)
	}

	for _, signin := range session.Signins {
		if signin.UserID != nil && email.User.ID != 0 && *signin.UserID == email.User.ID {
			return handler.SendBadRequest(
				c,
				nil,
				"User already signed in",
				handler.ErrUserAlreadySignedIn,
			)
		}
	}

	if err = h.service.ValidateUserStatus(email); err != nil {
		return handler.SendForbidden(
			c,
			nil,
			err.Error(),
			handler.ErrUserDisabled,
		)
	}

	missingFields := h.service.CheckMissingRequiredFields(&email.User, d.AuthSettings)
	requiresCompletion := len(missingFields) > 0

	authenticated := false

	if b.Password != "" {
		match, err := h.service.VerifyPassword(
			email.User.Password,
			b.Password,
		)
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error comparing password")
		}

		if !match {
			_ = utils.IncrementRateLimit(b.Email)
			return handler.SendUnauthorized(c, nil, "Invalid credentials", handler.ErrInvalidCredentials)
		}
		authenticated = true
	}

	if !authenticated {
		return handler.SendUnauthorized(
			c,
			nil,
			"Invalid credentials",
			handler.ErrInvalidCredentials,
		)
	}

	if authenticated {
		_ = utils.ClearRateLimit(b.Email)
	}

	secondFactorEnforced := email.User.SecondFactorPolicy == model.SecondFactorPolicyEnforced

	var steps []model.SignInAttemptStep

	if !email.Verified && authenticated {
		steps = append(steps, model.SignInAttemptStepVerifyEmail)
	}

	if secondFactorEnforced {
		steps = append(steps, model.SignInAttemptStepVerifySecondFactor)
	}

	if requiresCompletion {
		steps = append(steps, model.SignInAttemptStepCompleteProfile)
	}

	completed := len(steps) == 0 && authenticated

	attempt := h.service.CreateSignInAttempt(
		email.UserID,
		&email.ID,
		session.ID,
		model.SignInMethodPlainEmail,
		steps,
		completed,
		&d,
	)

	attempt.FirstMethodAuthenticated = authenticated

	if requiresCompletion {
		attempt.RequiresCompletion = true
		attempt.MissingFields = datatypes.NewJSONSlice(missingFields)
		requiredFields := h.service.GetRequiredFields(d.AuthSettings)
		attempt.RequiredFields = datatypes.NewJSONSlice(requiredFields)
		completed = false
	}

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(attempt).Error; err != nil {
			return err
		}

		if completed {
			if err := h.service.ValidateIPCountryRestrictions(c, d.Restrictions); err != nil {
				return err
			}

			signIn := h.service.CreateSignin(email.User.ID, session.ID, c, d.AuthSettings.SessionValidityPeriod)
			if err := tx.Create(signIn).Error; err != nil {
				return err
			}

			if err := tx.Model(&model.Session{}).Where("id = ?", session.ID).Update("active_signin_id", signIn.ID).Error; err != nil {
				return err
			}

			if email.User.PrimaryEmailAddressID != nil && email.ID == *email.User.PrimaryEmailAddressID {
				_ = h.service.nats.SendSignInNotificationEmail(d.ID, email.User.ID, signIn.ID, email.EmailAddress)
			}

			utils.PublishSignInEvent(d.ID, &email.User, string(b.Strategy), &email.EmailAddress, c)
		}

		return nil
	})

	if err == nil && completed {
		h.service.TrackMAU(d.ID, email.User.ID)
	}

	if err != nil &&
		err.(*pgconn.PgError).ConstraintName == "idx_session_user_id" {
		return handler.SendBadRequest(
			c,
			nil,
			"User already signed in",
			handler.ErrUserAlreadySignedIn,
		)
	}

	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Something went wrong",
		)
	}

	session.SigninAttempts = append(session.SigninAttempts, *attempt)
	handler.RemoveSessionFromCacheAndLocals(c, session.ID)
	return handler.SendSuccess(c, session)
}

func (h *Handler) handleImpersonationSignIn(
	c *fiber.Ctx,
	b SignInRequest,
	d model.Deployment,
	session *model.Session,
) error {
	if b.Token == "" {
		return handler.SendBadRequest(c, nil, "Impersonation token is required")
	}

	var keypair model.DeploymentKeyPair
	if err := database.Connection.Where("deployment_id = ?", d.ID).First(&keypair).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to get deployment keypair")
	}

	token, err := utils.VerifyJWT(b.Token, keypair, d.FrontendHost)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "Invalid or expired impersonation token", handler.ErrInvalidCredentials)
	}

	var userIDClaim interface{}
	if err := token.Get("user_id", &userIDClaim); err != nil || userIDClaim == nil {
		return handler.SendBadRequest(c, nil, "Invalid token: missing user_id")
	}

	var deploymentIDClaim interface{}
	if err := token.Get("deployment_id", &deploymentIDClaim); err != nil || deploymentIDClaim == nil {
		return handler.SendBadRequest(c, nil, "Invalid token: missing deployment_id")
	}

	var typeClaim interface{}
	if err := token.Get("type", &typeClaim); err != nil || typeClaim == nil || typeClaim != "impersonation" {
		return handler.SendBadRequest(c, nil, "Invalid token: incorrect type")
	}

	userIDStr, ok := userIDClaim.(string)
	if !ok {
		return handler.SendBadRequest(c, nil, "Invalid user_id type in token (expected string)")
	}
	userID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid user_id format in token")
	}

	deploymentIDStr, ok := deploymentIDClaim.(string)
	if !ok {
		return handler.SendBadRequest(c, nil, "Invalid deployment_id type in token (expected string)")
	}
	deploymentID, err := strconv.ParseUint(deploymentIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid deployment_id format in token")
	}

	if deploymentID != d.ID {
		return handler.SendUnauthorized(c, nil, "Token deployment mismatch", handler.ErrInvalidCredentials)
	}

	var user model.User
	if err := database.Connection.Where("id = ? AND deployment_id = ?", userID, d.ID).First(&user).Error; err != nil {
		return handler.SendNotFound(c, nil, "User not found", handler.ErrUserNotFound)
	}

	if user.Disabled {
		return handler.SendForbidden(c, nil, "Cannot impersonate disabled user", handler.ErrUserDisabled)
	}

	for _, signin := range session.Signins {
		if signin.UserID != nil && *signin.UserID == userID {
			return handler.SendBadRequest(
				c,
				nil,
				"User already signed in",
				handler.ErrUserAlreadySignedIn,
			)
		}
	}

	attempt := h.service.CreateSignInAttempt(
		&userID,
		nil,
		session.ID,
		model.SignInMethodImpersonation,
		[]model.SignInAttemptStep{},
		true,
		&d,
	)
	attempt.FirstMethodAuthenticated = true

	var signIn *model.Signin
	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(attempt).Error; err != nil {
			return err
		}

		signIn = h.service.CreateSignin(userID, session.ID, c, 1200)
		if err := tx.Create(signIn).Error; err != nil {
			return err
		}

		if err := tx.Model(&model.Session{}).Where("id = ?", session.ID).Update("active_signin_id", signIn.ID).Error; err != nil {
			return err
		}

		utils.PublishSignInEvent(d.ID, &user, "impersonation", nil, c)

		return nil
	})

	if err != nil {
		if err.(*pgconn.PgError).ConstraintName == "idx_session_user_id" {
			return handler.SendBadRequest(
				c,
				nil,
				"User already signed in",
				handler.ErrUserAlreadySignedIn,
			)
		}
		return handler.SendInternalServerError(
			c,
			err,
			"Something went wrong",
		)
	}

	h.service.TrackMAU(d.ID, userID)

	session.SigninAttempts = append(session.SigninAttempts, *attempt)
	handler.RemoveSessionFromCacheAndLocals(c, session.ID)
	return handler.SendSuccess(c, session)
}

func (h *Handler) handleOTPSignIn(
	c *fiber.Ctx,
	b SignInRequest,
	session *model.Session,
	method model.SignInMethod,
) error {
	var userID *uint64
	var identifierID *uint64
	var attempt *model.SignInAttempt
	deployment := handler.GetDeployment(c)
	requiresCompletion := false
	missingFields := []string{}

	switch method {
	case model.SignInMethodEmailOTP:
		email, _ := h.service.FindUserByVerifiedEmail(b.Email, deployment.ID)

		if email != nil {
			userID = email.UserID
			identifierID = &email.ID

			for _, signin := range session.Signins {
				if signin.UserID != nil && *signin.UserID == *userID {
					return handler.SendBadRequest(
						c,
						nil,
						"User already signed in",
						handler.ErrUserAlreadySignedIn,
					)
				}
			}

			if err := h.service.ValidateUserStatus(email); err != nil {
				return handler.SendForbidden(c, nil, err.Error(), handler.ErrUserDisabled)
			}

			missingFields = h.service.CheckMissingRequiredFields(&email.User, deployment.AuthSettings)
			requiresCompletion = len(missingFields) > 0

			secondFactorEnforced := email.User.SecondFactorPolicy == model.SecondFactorPolicyEnforced

			steps := []model.SignInAttemptStep{model.SignInAttemptStepVerifyEmailOTP}
			if secondFactorEnforced {
				steps = append(steps, model.SignInAttemptStepVerifySecondFactor)
			}
			if requiresCompletion {
				steps = append(steps, model.SignInAttemptStepCompleteProfile)
			}

			attempt = h.service.CreateSignInAttempt(
				userID,
				identifierID,
				session.ID,
				method,
				steps,
				false,
				&deployment,
			)
		} else {
			steps := []model.SignInAttemptStep{model.SignInAttemptStepVerifyEmailOTP}
			attempt = h.service.CreateSignInAttempt(
				nil,
				nil,
				session.ID,
				method,
				steps,
				false,
				&deployment,
			)
		}
	case model.SignInMethodPhoneOTP:
		phone, _ := h.service.FindUserByPhoneNumber(b.Phone, b.PhoneCountryCode, deployment.ID)

		if phone != nil {
			userID = &phone.User.ID
			identifierID = &phone.ID

			for _, signin := range session.Signins {
				if signin.UserID != nil && *signin.UserID == *userID {
					return handler.SendBadRequest(
						c,
						nil,
						"User already signed in",
						handler.ErrUserAlreadySignedIn,
					)
				}
			}

			if err := h.service.ValidatePhoneUserStatus(phone); err != nil {
				return handler.SendForbidden(c, nil, err.Error(), handler.ErrUserDisabled)
			}

			missingFields = h.service.CheckMissingRequiredFields(&phone.User, deployment.AuthSettings)
			requiresCompletion = len(missingFields) > 0

			secondFactorEnforced := phone.User.SecondFactorPolicy == model.SecondFactorPolicyEnforced

			steps := []model.SignInAttemptStep{model.SignInAttemptStepVerifyPhoneOTP}
			if secondFactorEnforced {
				steps = append(steps, model.SignInAttemptStepVerifySecondFactor)
			}
			if requiresCompletion {
				steps = append(steps, model.SignInAttemptStepCompleteProfile)
			}

			attempt = h.service.CreateSignInAttempt(
				userID,
				identifierID,
				session.ID,
				method,
				steps,
				false,
				&deployment,
			)
		} else {
			steps := []model.SignInAttemptStep{model.SignInAttemptStepVerifyPhoneOTP}
			attempt = h.service.CreateSignInAttempt(
				nil,
				nil,
				session.ID,
				method,
				steps,
				false,
				&deployment,
			)
		}
	}

	// Set profile completion requirements if needed
	// BUT don't set FirstMethodAuthenticated yet - that happens after OTP verification
	if requiresCompletion {
		attempt.RequiresCompletion = true
		attempt.MissingFields = datatypes.NewJSONSlice(missingFields)
		requiredFields := h.service.GetRequiredFields(deployment.AuthSettings)
		attempt.RequiredFields = datatypes.NewJSONSlice(requiredFields)
		// DO NOT set FirstMethodAuthenticated here - OTP hasn't been verified yet
		attempt.FirstMethodAuthenticated = false
	}

	err := database.Connection.Create(attempt).Error

	if requiresCompletion {
		var savedAttempt model.SignInAttempt
		database.Connection.Where("id = ?", attempt.ID).First(&savedAttempt)
	}

	if err != nil &&
		err.(*pgconn.PgError).ConstraintName == "idx_session_user_id" {
		return handler.SendBadRequest(
			c,
			nil,
			"User already signed in",
			handler.ErrUserAlreadySignedIn,
		)
	}

	if err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	session.SigninAttempts = append(session.SigninAttempts, *attempt)
	handler.RemoveSessionFromCacheAndLocals(c, session.ID)
	return handler.SendSuccess(c, session)
}

func (h *Handler) handleMagicLinkSignIn(
	c *fiber.Ctx,
	b SignInRequest,
	d model.Deployment,
	session *model.Session,
) error {
	email, _ := h.service.FindUserByVerifiedEmail(b.Email, d.ID)

	steps := []model.SignInAttemptStep{model.SignInAttemptStepVerifyEmailLink}
	requiresCompletion := false
	missingFields := []string{}
	var attempt *model.SignInAttempt

	if email != nil {
		if email.UserID != nil {
			for _, signin := range session.Signins {
				if signin.UserID != nil && *signin.UserID == *email.UserID {
					return handler.SendBadRequest(
						c,
						nil,
						"User already signed in",
						handler.ErrUserAlreadySignedIn,
					)
				}
			}
		}

		if err := h.service.ValidateUserStatus(email); err != nil {
			return handler.SendForbidden(
				c,
				nil,
				err.Error(),
				handler.ErrUserDisabled,
			)
		}

		missingFields = h.service.CheckMissingRequiredFields(&email.User, d.AuthSettings)
		requiresCompletion = len(missingFields) > 0

		secondFactorEnforced := email.User.SecondFactorPolicy == model.SecondFactorPolicyEnforced

		if secondFactorEnforced {
			steps = append(steps, model.SignInAttemptStepVerifySecondFactor)
		}

		if requiresCompletion {
			steps = append(steps, model.SignInAttemptStepCompleteProfile)
		}

		attempt = h.service.CreateSignInAttempt(
			email.UserID,
			&email.ID,
			session.ID,
			model.SignInMethodMagicLink,
			steps,
			false,
			&d,
		)
	} else {
		attempt = h.service.CreateSignInAttempt(
			nil,
			nil,
			session.ID,
			model.SignInMethodMagicLink,
			steps,
			false,
			&d,
		)
	}

	// FirstMethodAuthenticated will be set after magic link is verified
	attempt.FirstMethodAuthenticated = false

	if requiresCompletion {
		attempt.RequiresCompletion = true
		attempt.MissingFields = datatypes.NewJSONSlice(missingFields)
		requiredFields := h.service.GetRequiredFields(d.AuthSettings)
		attempt.RequiredFields = datatypes.NewJSONSlice(requiredFields)
	}

	err := database.Connection.Create(attempt).Error

	if err != nil &&
		err.(*pgconn.PgError).ConstraintName == "idx_session_user_id" {
		return handler.SendBadRequest(
			c,
			nil,
			"User already signed in",
			handler.ErrUserAlreadySignedIn,
		)
	}

	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Something went wrong",
		)
	}

	session.SigninAttempts = append(session.SigninAttempts, *attempt)
	handler.RemoveSessionFromCacheAndLocals(c, session.ID)
	return handler.SendSuccess(c, session)
}

func (h *Handler) SignUp(c *fiber.Ctx) error {
	b, validation := handler.Validate[SignUpRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	d := handler.GetDeployment(c)
	session := handler.GetSession(c)

	if d.AuthSettings.Password.Enabled && b.Password != "" {
		if err := h.service.ValidatePasswordWithSettings(b.Password, d.AuthSettings.Password); err != nil {
			return handler.SendBadRequest(c, nil, err.Error())
		}
	}

	if d.Restrictions.SignUpMode == model.DeploymentRestrictionsSignUpModeRestricted {
		return handler.SendForbidden(
			c,
			nil,
			"Signup is currently restricted for this deployment",
			handler.ErrSignupRestricted,
		)
	}

	if d.Restrictions.SignUpMode == model.DeploymentRestrictionsSignUpModeWaitlist {
		return handler.SendBadRequest(
			c,
			nil,
			"Signup is currently in waitlist mode. Please join the waitlist instead",
			handler.ErrSignupWaitlistOnly,
		)
	}

	if err := h.service.ValidateSignUpRequest(b, d); err != nil {
		return handler.SendBadRequest(
			c,
			nil,
			err.Error(),
			handler.ErrBadRequestBody,
		)
	}

	inviteToken := c.Query("invite_token")
	if inviteToken != "" && b.Email != "" {
		var invitation model.DeploymentInvitation
		err := database.Connection.
			Where("token = ? AND deployment_id = ? AND expiry > ?",
				inviteToken, d.ID, time.Now()).
			First(&invitation).Error

		if err == nil && invitation.EmailAddress != b.Email {
			return handler.SendBadRequest(
				c,
				nil,
				"You must sign up with the invited email address",
				handler.ErrBadRequestBody,
			)
		}
	}

	var errors []handler.Error

	if b.Email != "" && h.service.CheckEmailExists(b.Email, d.ID) {
		errors = append(errors, handler.ErrEmailExists)
	}

	if b.Username != "" && h.service.CheckUsernameExists(b.Username, d.ID) {
		errors = append(errors, handler.ErrUsernameExists)
	}

	if b.PhoneNumber != "" &&
		h.service.CheckUserphoneExists(b.PhoneNumber, b.PhoneCountryCode, d.ID) {
		errors = append(errors, handler.ErrPhoneNumberExists)
	}

	if len(errors) > 0 {
		return handler.SendBadRequest(
			c,
			nil,
			"Field errors",
			errors...)
	}

	var hashedPassword string
	if b.Password != "" {
		var err error
		hashedPassword, err = h.service.HashPassword(b.Password)
		if err != nil {
			return handler.SendInternalServerError(
				c,
				err,
				"Error hashing password",
			)
		}
	}

	attempt, err := h.service.CreateSignupAttempt(
		b,
		hashedPassword,
		session,
		d,
	)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Error creating signup attempt",
		)
	}

	var createdUserID uint64
	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(attempt).Error; err != nil {
			return err
		}

		session.SignupAttempts = append(
			session.SignupAttempts,
			*attempt,
		)

		if len(attempt.RemainingSteps) == 0 {
			if err != nil {
				return err
			}

			u := h.service.CreateUser(
				b,
				attempt.Password,
				d.ID,
				d.AuthSettings.SecondFactorPolicy,
				!d.AuthSettings.EmailAddress.VerifySignup,
			)

			if err := tx.Create(&u).Error; err != nil {
				return err
			}

			if !d.AuthSettings.EmailAddress.VerifySignup {
				if err := h.service.CheckAndAddUserToOrganizationByDomain(tx, u.ID, b.Email, d.ID); err != nil {
					return err
				}
			}

			createdUserID = u.ID

			if err := h.service.ValidateIPCountryRestrictions(c, d.Restrictions); err != nil {
				return err
			}

			signIn := h.service.CreateSignin(u.ID, session.ID, c, d.AuthSettings.SessionValidityPeriod)

			if err := tx.Create(signIn).Error; err != nil {
				return err
			}

			if err := tx.Model(&model.Session{}).Where("id = ?", session.ID).Update("active_signin_id", signIn.ID).Error; err != nil {
				return err
			}

			utils.PublishSignUpEvent(d.ID, &u, "email_password", &b.Email, c)
			utils.PublishSignInEvent(d.ID, &u, "email_password", &b.Email, c)
		}

		handler.RemoveSessionFromCacheAndLocals(c, session.ID)

		return nil
	})
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Something went wrong",
		)
	}

	if createdUserID != 0 {
		utils.PublishWebhookEvent(d.ID, "user.created", createdUserID, "user")
		h.service.TrackMAU(d.ID, createdUserID)
	}

	return handler.SendSuccess(c, session)
}

func (h *Handler) AuthMethods(c *fiber.Ctx) error {
	d := handler.GetDeployment(c)
	return handler.SendSuccess(c, d.AuthSettings)
}

func (h *Handler) InitOAuth2(c *fiber.Ctx) error {
	provider := model.SocialConnectionProvider(c.Query("provider"))
	if provider == "" {
		return handler.SendBadRequest(
			c,
			nil,
			"provider is required",
			handler.ErrProviderRequired,
		)
	}

	session := handler.GetSession(c)
	deployment := handler.GetDeployment(c)
	customRedirectURI := c.Query("redirect_uri")

	attempt := model.NewSignInAttempt(model.SignInMethodSSO)
	attempt.Method = model.SignInMethodSSO
	attempt.SessionID = session.ID
	attempt.SSOProvider = provider

	err := database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(attempt).Error; err != nil {
			return err
		}
		session.SigninAttempts = append(
			session.SigninAttempts,
			*attempt,
		)
		return nil
	})
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Something went wrong",
		)
	}

	var keypair model.DeploymentKeyPair
	if err := database.Connection.Where("deployment_id = ?", deployment.ID).
		First(&keypair).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to get deployment keypair",
		)
	}

	url, err := utils.GenerateVerificationUrlForDeployment(provider, *attempt, &deployment, customRedirectURI, keypair)
	if err != nil {
		return handler.SendBadRequest(
			c,
			nil,
			err.Error(),
			handler.ErrProviderNotConfigured,
		)
	}

	return handler.SendSuccess(c, fiber.Map{
		"oauth_url": url,
		"session":   session,
	})
}

func (h *Handler) OAuth2Callback(c *fiber.Ctx) error {
	code := c.Query("code")
	deployment := handler.GetDeployment(c)
	session := handler.GetSession(c)

	if code == "" {
		return handler.SendBadRequest(
			c,
			nil,
			"code is not present in uri",
			handler.ErrCodeRequired,
		)
	}

	state := c.Query("state")
	if state == "" {
		return handler.SendBadRequest(
			c,
			nil,
			"State parameter is missing",
			handler.ErrInvalidState,
		)
	}
	var keypair model.DeploymentKeyPair
	if err := database.Connection.Where("deployment_id = ?", deployment.ID).
		First(&keypair).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to get deployment keypair",
		)
	}

	secret := utils.GetOAuthStateSecret(deployment.ID, keypair.PrivateKey)
	stateData, err := utils.ValidateOAuthState(state, secret, 10*time.Minute)
	if err != nil {
		return handler.SendBadRequest(
			c,
			nil,
			fmt.Sprintf("Invalid or expired state: %v", err),
			handler.ErrInvalidState,
		)
	}

	if stateData.Action != "sign_in" {
		return handler.SendBadRequest(
			c,
			nil,
			"Invalid state action for sign-in",
			handler.ErrInvalidState,
		)
	}

	if stateData.AttemptID == nil {
		return handler.SendBadRequest(
			c,
			nil,
			"Missing attempt ID in state",
			handler.ErrInvalidState,
		)
	}

	var attempt model.SignInAttempt
	if err := database.Connection.Where("id = ? AND session_id = ?", *stateData.AttemptID, session.ID).First(&attempt).Error; err != nil {
		return handler.SendBadRequest(
			c,
			nil,
			"Invalid or expired authentication attempt",
			handler.ErrInvalidState,
		)
	}

	customRedirectURI := stateData.RedirectURI

	if time.Since(attempt.CreatedAt) > 10*time.Minute {
		return handler.SendBadRequest(
			c,
			nil,
			"Authentication attempt has expired",
			handler.ErrInvalidState,
		)
	}

	conf, err := utils.GetOAuthConfigForDeployment(attempt.SSOProvider, &deployment)
	if err != nil {
		return handler.SendBadRequest(
			c,
			nil,
			err.Error(),
			handler.ErrProviderNotConfigured,
		)
	}

	token, err := conf.Exchange(c.Context(), code)
	if err != nil || !token.Valid() {
		return handler.SendBadRequest(
			c,
			nil,
			"Authentication state not correct. Please try logging in again",
			handler.ErrInvalidCode,
		)
	}

	user, err := utils.ExchangeTokenForUser(
		token,
		attempt.SSOProvider,
	)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to get user info",
		)
	}

	if user.Email != "" {
		user.Email = strings.ToLower(user.Email)
	}

	var email model.UserEmailAddress
	err = database.Connection.
		Where("email_address = ? AND deployment_id = ?", user.Email, deployment.ID).
		Preload("User").
		Preload("User.SocialConnections").
		First(&email).Error

	if err != nil && err != gorm.ErrRecordNotFound {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
		)
	}

	exists := err != gorm.ErrRecordNotFound

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		if exists {
			if err := h.service.ValidateIPCountryRestrictions(c, deployment.Restrictions); err != nil {
				return err
			}

			signIn, err := h.service.HandleExistingUser(
				tx,
				&email,
				token,
				&attempt,
				&deployment,
				session,
				c,
			)
			if err != nil {
				return err
			}

			if signIn != nil {
				session.Signins = append(session.Signins, *signIn)
				session.ActiveSigninID = &signIn.ID
				attempt.Completed = true

				utils.PublishWebhookEvent(deployment.ID, "session.created", session.ID, "session")
			} else {
				attempt.Completed = false
			}

			if err := tx.Save(&attempt).Error; err != nil {
				return err
			}

			return nil
		}

		primaryAddressID := snowflake.ID()

		u := model.User{
			Model: model.Model{
				ID: snowflake.ID(),
			},
			FirstName:             user.FirstName,
			LastName:              user.LastName,
			SchemaVersion:         model.SchemaVersionV1,
			SecondFactorPolicy:    deployment.AuthSettings.SecondFactorPolicy,
			DeploymentID:          deployment.ID,
			PrimaryEmailAddressID: &primaryAddressID,
		}

		if err := tx.Create(&u).Error; err != nil {
			return err
		}

		email := model.UserEmailAddress{
			Model:                model.Model{ID: primaryAddressID},
			DeploymentID:         deployment.ID,
			EmailAddress:         user.Email,
			IsPrimary:            true,
			Verified:             true,
			VerifiedAt:           time.Now(),
			VerificationStrategy: utils.GetVerificationStrategyForProvider(string(attempt.SSOProvider)),
			UserID:               &u.ID,
		}

		if err := tx.Create(&email).Error; err != nil {
			return err
		}

		connection := h.service.CreateSocialConnection(
			u.ID,
			email.ID,
			attempt.SSOProvider,
			user.Email,
			token,
		)
		if err := h.service.ValidateIPCountryRestrictions(c, deployment.Restrictions); err != nil {
			return err
		}

		if err := tx.Create(&connection).Error; err != nil {
			return err
		}

		if err := h.service.CheckAndAddUserToOrganizationByDomain(tx, u.ID, user.Email, deployment.ID); err != nil {
			return err
		}

		missingFields := h.service.CheckMissingRequiredFields(&u, deployment.AuthSettings)
		requiresCompletion := len(missingFields) > 0
		secondFactorEnforced := u.SecondFactorPolicy == model.SecondFactorPolicyEnforced

		var steps []model.SignInAttemptStep
		if secondFactorEnforced {
			steps = append(steps, model.SignInAttemptStepVerifySecondFactor)
		}
		if requiresCompletion {
			steps = append(steps, model.SignInAttemptStepCompleteProfile)
		}

		attempt.UserID = &u.ID
		attempt.IdentifierID = &email.ID
		attempt.FirstMethodAuthenticated = true

		if len(steps) > 0 {
			attempt.RemainingSteps = datatypes.NewJSONSlice(steps)
			attempt.CurrentStep = steps[0]
			attempt.Completed = false

			if secondFactorEnforced {
				attempt.SecondMethodAuthenticationRequired = true
				attempt.Available2FAMethods = datatypes.NewJSONSlice(
					h.service.GetAvailable2FAMethods(u.ID, &deployment),
				)
			}

			if requiresCompletion {
				attempt.RequiresCompletion = true
				attempt.MissingFields = datatypes.NewJSONSlice(missingFields)
				requiredFields := h.service.GetRequiredFields(deployment.AuthSettings)
				attempt.RequiredFields = datatypes.NewJSONSlice(requiredFields)
			}
		} else {
			signIn := h.service.CreateSignin(u.ID, session.ID, c, deployment.AuthSettings.SessionValidityPeriod)

			if err := tx.Create(&signIn).Error; err != nil {
				return err
			}

			session.Signins = append(session.Signins, *signIn)
			session.ActiveSigninID = &signIn.ID

			utils.PublishWebhookEvent(deployment.ID, "session.created", session.ID, "session")
			attempt.Completed = true

			var primaryEmail *string
			if u.PrimaryEmailAddressID != nil {
				for _, email := range u.UserEmailAddresses {
					if email.ID == *u.PrimaryEmailAddressID {
						primaryEmail = &email.EmailAddress
						_ = h.service.nats.SendSignInNotificationEmail(deployment.ID, u.ID, signIn.ID, email.EmailAddress)
						break
					}
				}
			}

			utils.PublishSignUpEvent(deployment.ID, &u, "oauth", primaryEmail, c)
			utils.PublishSignInEvent(deployment.ID, &u, "oauth", primaryEmail, c)
		}

		if err := tx.Save(&attempt).Error; err != nil {
			return err
		}

		return nil
	})

	if err == nil && attempt.Completed && attempt.UserID != nil {
		h.service.TrackMAU(deployment.ID, *attempt.UserID)
	}

	if err != nil {
		pgErr, ok := err.(*pgconn.PgError)
		if ok && pgErr.ConstraintName == "idx_session_user_id" {
			return handler.SendBadRequest(
				c,
				nil,
				"User already signed in",
				handler.ErrUserAlreadySignedIn,
			)
		}
		return handler.SendInternalServerError(
			c,
			err,
			"Something went wrong",
		)
	}

	if err := database.Connection.Model(&model.Session{}).Where("id = ?", session.ID).Updates(map[string]any{
		"active_signin_id": session.ActiveSigninID,
	}).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to save session",
		)
	}

	session.SigninAttempts = append(session.SigninAttempts, attempt)
	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	response := fiber.Map{
		"session": session,
	}
	if customRedirectURI != "" {
		response["redirect_uri"] = customRedirectURI
	}

	return handler.SendSuccess(c, response)
}

func (h *Handler) CheckIdentifierAvailability(c *fiber.Ctx) error {
	identifier := c.Query("identifier")
	identifierType := c.Query("type")
	deployment := handler.GetDeployment(c)

	exists, err := h.service.CheckIdentifierAvailability(
		identifier,
		identifierType,
		deployment.ID,
	)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Something went wrong",
		)
	}
	return handler.SendSuccess(c, fiber.Map{
		"exists": exists,
	})
}

func (h *Handler) PrepareVerification(c *fiber.Ctx) error {
	attemptIdentifier := c.QueryInt("attempt_identifier")
	identifierType := c.Query("identifier_type")
	strategy := c.Query("strategy")
	redirectURI := c.Query("redirect_uri")
	deployment := handler.GetDeployment(c)

	if attemptIdentifier == 0 {
		return handler.SendBadRequest(
			c,
			nil,
			"either sign_in_attempt or sign_up_attempt is required",
			handler.ErrInvalidSignInAttempt,
		)
	}

	if strategy == "" {
		return handler.SendBadRequest(
			c,
			nil,
			"strategy is required",
			handler.ErrVerificationStrategyRequired,
		)
	}

	if identifierType == "signin" {
		attempt, err := h.service.GetSignInAttempt(
			uint64(attemptIdentifier),
		)
		if err != nil {
			return handler.SendInternalServerError(
				c,
				err,
				"Error fetching sign in attempt",
				handler.ErrInvalidSignInAttempt,
			)
		}

		if attempt.Completed {
			return handler.SendBadRequest(
				c,
				nil,
				"Sign in attempt already completed",
				handler.ErrInvalidSignInAttempt,
			)
		}

		switch attempt.CurrentStep {
		case model.SignInAttemptStepVerifyEmailOTP:
			var emailAddress string
			var userID uint64

			if attempt.IdentifierID == nil && attempt.ProfileCompletionData != nil &&
				attempt.ProfileCompletionData.Email != "" {
				emailAddress = attempt.ProfileCompletionData.Email
				if attempt.UserID != nil {
					userID = *attempt.UserID
				}
			} else if attempt.IdentifierID != nil {

				email, err := h.service.FindUserByEmailID(*attempt.IdentifierID, deployment.ID)
				if err != nil {
					return handler.SendInternalServerError(c, err, "Error fetching user", handler.ErrInvalidSignInAttempt)
				}
				emailAddress = email.EmailAddress
				if email.UserID != nil {
					userID = *email.UserID
				}
			} else {
				return handler.SendSuccess[any](c, nil)
			}

			code, err := utils.GenerateOTP()
			if err != nil {
				return handler.SendInternalServerError(c, err, "Error generating OTP", handler.ErrInternal)
			}

			if err := h.service.StoreOTPInCache(fmt.Sprintf("signin:%d", attempt.ID), code); err != nil {
				return handler.SendInternalServerError(c, err, "Error storing OTP", handler.ErrInternal)
			}

			if err := h.service.SendSigninVerificationEmail(userID, emailAddress, code, deployment, c.IP(), c.Get("User-Agent")); err != nil {
				return handler.SendInternalServerError(c, err, "Error sending email OTP verification")
			}
		case model.SignInAttemptStepVerifyPhoneOTP:
			var phoneNumber string
			var countryCode string
			var userID uint64

			if attempt.IdentifierID == nil && attempt.ProfileCompletionData != nil &&
				attempt.ProfileCompletionData.PhoneNumber != "" {
				phoneNumber = attempt.ProfileCompletionData.PhoneNumber
				countryCode = attempt.ProfileCompletionData.PhoneCountryCode
				if attempt.UserID != nil {
					userID = *attempt.UserID
				}
			} else if attempt.IdentifierID != nil {
				phone, err := h.service.FindUserByPhoneNumberID(*attempt.IdentifierID, deployment.ID)
				if err != nil {
					return handler.SendInternalServerError(c, err, "Error fetching user", handler.ErrInvalidSignInAttempt)
				}
				phoneNumber = phone.PhoneNumber
				countryCode = phone.CountryCode
				userID = phone.UserID
			} else {
				return handler.SendSuccess[any](c, nil)
			}

			if err := h.service.SendSmsOTPVerificationAsync(phoneNumber, countryCode, userID, deployment); err != nil {
				return handler.SendInternalServerError(c, err, "Error sending SMS OTP verification")
			}
		case model.SignInAttemptStepVerifyEmailLink:
			if attempt.IdentifierID == nil {
				return handler.SendSuccess[any](c, nil)
			}

			email, err := h.service.FindUserByEmailID(
				*attempt.IdentifierID,
				deployment.ID,
			)
			if err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error fetching user",
					handler.ErrInvalidSignInAttempt,
				)
			}

			magicLink, err := h.service.GenerateMagicLink(attempt.ID, deployment, redirectURI)
			if err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error generating magic link",
					handler.ErrInternal,
				)
			}

			if err := h.service.SendMagicLinkAsync(email.EmailAddress, magicLink, deployment); err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error sending magic link",
				)
			}
		case model.SignInAttemptStepVerifySecondFactor:
			if attempt.UserID == nil {
				return handler.SendBadRequest(
					c,
					nil,
					"User ID not found in sign-in attempt",
				)
			}

			switch strategy {
			case "phone_otp":
				if err := h.service.Store2FAMethodInCache(fmt.Sprintf("2fa_method:%d", attempt.ID), "phone_otp"); err != nil {
					return handler.SendInternalServerError(
						c,
						nil,
						"Something went wrong ",
					)
				}

				var user model.User
				if err := database.Connection.Preload("PrimaryPhoneNumber").Where("id = ?", *attempt.UserID).First(&user).Error; err != nil {
					return handler.SendInternalServerError(
						c,
						err,
						"Error fetching user",
					)
				}

				if user.PrimaryPhoneNumber == nil || !user.PrimaryPhoneNumber.Verified {
					return handler.SendBadRequest(
						c,
						nil,
						"No verified phone number available for 2FA",
					)
				}

				lastDigits := c.Query("last_digits")
				phoneNumber := user.PrimaryPhoneNumber.PhoneNumber

				if len(lastDigits) != 4 {
					return handler.SendBadRequest(c, nil, "Last digits must be 4 characters")
				}

				actualLastDigits := phoneNumber[len(phoneNumber)-4:]
				if actualLastDigits != lastDigits {
					return handler.SendBadRequest(c, nil, "Phone number verification failed")
				}

				if err := database.Connection.Model(&model.SignInAttempt{}).Where("id = ?", attempt.ID).
					Update("identifier_id", *user.PrimaryPhoneNumberID).
					Error; err != nil {
					return handler.SendInternalServerError(
						c,
						nil,
						"Something went wrong",
					)
				}

				if err := h.service.SendSmsOTPVerificationAsync(user.PrimaryPhoneNumber.PhoneNumber, user.PrimaryPhoneNumber.CountryCode, user.ID, deployment); err != nil {
					return handler.SendInternalServerError(
						c,
						err,
						"Error sending 2FA SMS",
					)
				}

				maskedPhone := h.service.MaskPhoneNumber(user.PrimaryPhoneNumber.CountryCode, phoneNumber)
				return handler.SendSuccess(c, fiber.Map{
					"masked_phone": maskedPhone,
					"method":       "phone_otp",
					"otp_sent":     true,
				})

			case "authenticator":
				if err := h.service.Store2FAMethodInCache(fmt.Sprintf("2fa_method:%d", attempt.ID), "authenticator"); err != nil {
					return handler.SendInternalServerError(
						c,
						err,
						"Error storing 2FA method",
					)
				}

				return handler.SendSuccess(c, fiber.Map{
					"method": "authenticator",
				})

			case "backup_code":
				if err := h.service.Store2FAMethodInCache(fmt.Sprintf("2fa_method:%d", attempt.ID), "backup_code"); err != nil {
					return handler.SendInternalServerError(
						c,
						err,
						"Error storing 2FA method",
					)
				}

				return handler.SendSuccess(c, fiber.Map{
					"method": "backup_code",
				})

			default:
				return handler.SendBadRequest(
					c,
					nil,
					"Invalid 2FA strategy",
				)
			}
		default:
			return handler.SendBadRequest(c, nil, "Invalid step")
		}
	} else {
		attempt, err := h.service.GetSignupAttempt(uint64(attemptIdentifier))
		if err != nil {
			return handler.SendInternalServerError(
				c,
				err,
				"Error fetching sign up attempt",
				handler.ErrInvalidSignInAttempt,
			)
		}

		switch attempt.CurrentStep {
		case model.SignupAttemptStepVerifyEmail:
			key, err := totp.Generate(totp.GenerateOpts{Issuer: "wacht", AccountName: attempt.Email})
			if err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error generating OTP",
					handler.ErrInternal,
				)
			}

			code, err := totp.GenerateCode(key.Secret(), time.Now())
			if err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error generating OTP",
					handler.ErrInternal,
				)
			}

			if err := h.service.StoreOTPInCache(fmt.Sprintf("signup:%d", attempt.ID), code); err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Something went wrong",
					handler.ErrInternal,
				)
			}

			if err := h.service.SendSignupVerificationEmail(attempt.ID, attempt.Email, code, &deployment, 0, c.IP(), c.Get("User-Agent")); err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error sending email OTP verification",
				)
			}
		case model.SignupAttemptStepVerifyPhone:
			if err := h.service.SendSmsOTPVerificationAsync(attempt.PhoneNumber, attempt.PhoneCountryCode, 0, deployment); err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error sending SMS OTP verification",
				)
			}
		default:
			return handler.SendBadRequest(c, nil, "Invalid step")
		}
	}

	return handler.SendSuccess[any](c, nil)
}

func (h *Handler) VerifyMagicLink(c *fiber.Ctx) error {
	token := c.Query("token")
	attemptIDStr := c.Query("attempt")

	if token == "" || attemptIDStr == "" {
		return handler.SendBadRequest(c, nil, "Missing token or attempt ID")
	}

	attemptID, err := strconv.ParseUint(attemptIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid attempt ID")
	}

	attempt, err := h.service.GetSignInAttempt(attemptID)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid signin attempt")
	}

	if attempt.Method != model.SignInMethodMagicLink {
		return handler.SendBadRequest(c, nil, "Invalid signin method")
	}

	if err := h.service.VerifyMagicLinkToken(attemptID, token); err != nil {
		return handler.SendBadRequest(c, nil, "Invalid or expired magic link")
	}

	session := handler.GetSession(c)
	deployment := handler.GetDeployment(c)

	if deployment.AuthSettings.MagicLink.RequireSameDevice {
		if attempt.SessionID != session.ID {
			return handler.SendBadRequest(
				c,
				nil,
				"Magic link must be verified from the same device/browser where it was requested",
			)
		}
	}

	if attempt.IdentifierID == nil {
		return handler.SendBadRequest(c, nil, "Invalid or expired magic link")
	}

	email, err := h.service.FindUserByEmailID(*attempt.IdentifierID, deployment.ID)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Error fetching user")
	}

	if len(attempt.RemainingSteps) == 1 {
		attempt.Completed = true
		attempt.RemainingSteps = nil

		if err := h.service.ValidateIPCountryRestrictions(c, deployment.Restrictions); err != nil {
			return handler.SendBadRequest(c, nil, err.Error(), handler.ErrCountryRestricted)
		}

		signIn := h.service.CreateSignin(email.User.ID, session.ID, c, deployment.AuthSettings.SessionValidityPeriod)

		err = database.Connection.Transaction(func(tx *gorm.DB) error {
			if err := tx.Create(signIn).Error; err != nil {
				return err
			}

			if err := tx.Model(&model.Session{}).Where("id = ?", session.ID).Update("active_signin_id", signIn.ID).Error; err != nil {
				return err
			}

			_ = h.service.nats.SendSignInNotificationEmail(deployment.ID, email.User.ID, signIn.ID, email.EmailAddress)

			return tx.Save(&attempt).Error
		})

		if err == nil {
			utils.PublishSignInEvent(deployment.ID, &email.User, "magic_link", &email.EmailAddress, c)
			h.service.TrackMAU(deployment.ID, email.User.ID)
		}

		if err != nil {
			pgErr, ok := err.(*pgconn.PgError)
			if ok && pgErr.ConstraintName == "idx_session_user_id" {
				// User is already signed in, just return success with current session
				return handler.SendSuccess(c, session)
			}
			return handler.SendInternalServerError(c, err, "Error completing signin")
		}

		handler.RemoveSessionFromCacheAndLocals(c, session.ID)
		return handler.SendSuccess(c, session)
	} else {
		attempt.RemainingSteps = attempt.RemainingSteps[1:]
		attempt.CurrentStep = attempt.RemainingSteps[0]

		if err := database.Connection.Save(&attempt).Error; err != nil {
			return handler.SendInternalServerError(c, err, "Error updating attempt")
		}

		session.SigninAttempts = append(session.SigninAttempts, attempt)
		handler.RemoveSessionFromCacheAndLocals(c, session.ID)
		return handler.SendSuccess(c, session)
	}
}

func (h *Handler) AttemptVerification(c *fiber.Ctx) error {
	attemptIdentifier := c.QueryInt("attempt_identifier")
	identifierType := c.Query("identifier_type")
	session := handler.GetSession(c)
	deployment := handler.GetDeployment(c)

	if attemptIdentifier == 0 {
		return handler.SendBadRequest(
			c,
			nil,
			"either sign_in_attempt or sign_up_attempt is required",
			handler.ErrInvalidSignInAttempt,
		)
	}

	b, validation := handler.Validate[VerifyOTPRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	if identifierType == "signin" {
		attempt, err := h.service.GetSignInAttempt(
			uint64(attemptIdentifier),
		)
		if err != nil {
			return handler.SendInternalServerError(
				c,
				err,
				"Error fetching sign in attempt",
			)
		}
		if attempt.Completed {
			return handler.SendBadRequest(
				c,
				nil,
				"Sign in attempt already completed",
			)
		}

		var signin *model.Signin

		switch attempt.CurrentStep {
		case model.SignInAttemptStepVerifyEmail,
			model.SignInAttemptStepVerifyEmailOTP:
			{

				valid, err := h.service.VerifyOTPFromRedis(fmt.Sprintf("signin:%d", attempt.ID), b.VerificationCode)
				if err != nil || !valid {
					return handler.SendBadRequest(c, nil, "Invalid or expired OTP")
				}

				var emailAddress string
				var userID uint64
				var user *model.User

				if attempt.ProfileCompletionData != nil && attempt.ProfileCompletionData.Email != "" {

					emailAddress = attempt.ProfileCompletionData.Email
					if attempt.UserID != nil {
						userID = *attempt.UserID

						var u model.User
						if err := database.Connection.Where("id = ?", userID).First(&u).Error; err != nil {
							return handler.SendInternalServerError(c, err, "Error fetching user")
						}
						user = &u
					}
				} else if attempt.IdentifierID != nil {

					email, err := h.service.FindUserByEmailID(*attempt.IdentifierID, deployment.ID)
					if err != nil {
						return handler.SendInternalServerError(c, err, "Error fetching user")
					}
					emailAddress = email.EmailAddress
					if email.UserID != nil {
						userID = *email.UserID
					}
				} else {
					return handler.SendBadRequest(c, nil, "Invalid verification attempt")
				}

				if len(attempt.RemainingSteps) == 1 {
					attempt.Completed = true
					attempt.RemainingSteps = nil
					signin = h.service.CreateSignin(
						userID,
						session.ID,
						c,
						deployment.AuthSettings.SessionValidityPeriod,
					)
					session.Signins = append(session.Signins, *signin)
					session.ActiveSigninID = &signin.ID

					utils.PublishWebhookEvent(deployment.ID, "session.created", session.ID, "session")
				} else {
					attempt.RemainingSteps = attempt.RemainingSteps[1:]
					attempt.CurrentStep = attempt.RemainingSteps[0]
				}

				if err := database.Connection.Transaction(func(tx *gorm.DB) error {

					if attempt.ProfileCompletionData != nil && attempt.ProfileCompletionData.Email != "" && user != nil {
						emailID := snowflake.ID()
						emailRecord := model.UserEmailAddress{
							Model:        model.Model{ID: emailID},
							EmailAddress: emailAddress,
							Verified:     true,
							VerifiedAt:   time.Now().UTC(),
							DeploymentID: deployment.ID,
							UserID:       &userID,
						}
						if err := tx.Create(&emailRecord).Error; err != nil {
							return err
						}

						if user.PrimaryEmailAddressID == nil {
							user.PrimaryEmailAddressID = &emailID
							if err := tx.Save(user).Error; err != nil {
								return err
							}
						}
					}

					if attempt.Completed {
						d := handler.GetDeployment(c)
						if err := h.service.ValidateIPCountryRestrictions(c, d.Restrictions); err != nil {
							return err
						}
						if err := tx.Create(signin).Error; err != nil {
							return err
						}
						_ = h.service.nats.SendSignInNotificationEmail(d.ID, userID, signin.ID, emailAddress)
					}

					if err := tx.Model(&model.Session{}).Where("id = ?", session.ID).Updates(map[string]interface{}{
						"active_signin_id": session.ActiveSigninID,
					}).Error; err != nil {
						return err
					}

					handler.RemoveSessionFromCacheAndLocals(c, session.ID)
					return tx.Save(attempt).Error
				}); err != nil {
					return handler.SendInternalServerError(
						c,
						err,
						"Something went wrong",
					)
				}

				if attempt.Completed {
					h.service.TrackMAU(deployment.ID, userID)
				}

				h.service.DeleteOTPFromRedis(
					fmt.Sprintf("signin:%d", attempt.ID),
				)

				for i, sa := range session.SigninAttempts {
					if sa.ID == attempt.ID {
						session.SigninAttempts[i] = attempt
						break
					}
				}
			}
		case model.SignInAttemptStepVerifyPhone,
			model.SignInAttemptStepVerifyPhoneOTP:
			{
				var phoneNumber string
				var userID uint64
				var user *model.User
				var phone *model.UserPhoneNumber

				if attempt.ProfileCompletionData != nil && attempt.ProfileCompletionData.PhoneNumber != "" {

					phoneNumber = attempt.ProfileCompletionData.PhoneNumber
					if attempt.UserID != nil {
						userID = *attempt.UserID

						var u model.User
						if err := database.Connection.Where("id = ?", userID).First(&u).Error; err != nil {
							return handler.SendInternalServerError(c, err, "Error fetching user")
						}
						user = &u
					}
				} else if attempt.IdentifierID != nil {
					p, err := h.service.FindUserByPhoneNumberID(*attempt.IdentifierID, deployment.ID)
					if err != nil {
						return handler.SendInternalServerError(c, err, "Error fetching user")
					}
					phone = p
					phoneNumber = p.PhoneNumber
					userID = p.User.ID
				} else {
					return handler.SendBadRequest(c, nil, "Invalid verification attempt")
				}

				isValid, err := h.service.VerifyPhoneOTP(deployment.ID, phoneNumber, attempt.ProfileCompletionData.PhoneCountryCode, b.VerificationCode)
				if err != nil {
					return handler.SendBadRequest(c, nil, "Invalid or expired OTP")
				}

				if !isValid {
					return handler.SendBadRequest(c, nil, "Invalid OTP")
				}

				attempt.FirstMethodAuthenticated = true
				if len(attempt.RemainingSteps) > 1 {

					attempt.RemainingSteps = attempt.RemainingSteps[1:]
					attempt.CurrentStep = attempt.RemainingSteps[0]

					if attempt.CurrentStep == model.SignInAttemptStepVerifySecondFactor {
						attempt.SecondMethodAuthenticationRequired = true
					}
				} else {
					attempt.Completed = true
					attempt.RemainingSteps = nil
					signin = h.service.CreateSignin(userID, session.ID, c, deployment.AuthSettings.SessionValidityPeriod)
					session.Signins = append(session.Signins, *signin)
					session.ActiveSigninID = &signin.ID

					utils.PublishWebhookEvent(deployment.ID, "session.created", session.ID, "session")
				}

				if err := database.Connection.Transaction(func(tx *gorm.DB) error {

					if attempt.ProfileCompletionData != nil && attempt.ProfileCompletionData.PhoneNumber != "" && user != nil {
						phoneID := snowflake.ID()
						phoneRecord := model.UserPhoneNumber{
							Model:        model.Model{ID: phoneID},
							PhoneNumber:  phoneNumber,
							CountryCode:  attempt.ProfileCompletionData.PhoneCountryCode,
							Verified:     true,
							VerifiedAt:   time.Now().UTC(),
							DeploymentID: deployment.ID,
							UserID:       userID,
						}
						if err := tx.Create(&phoneRecord).Error; err != nil {
							return err
						}

						if user.PrimaryPhoneNumberID == nil {
							user.PrimaryPhoneNumberID = &phoneID
							if err := tx.Save(user).Error; err != nil {
								return err
							}
						}
					} else if phone != nil {

						phone.Verified = true
						phone.VerifiedAt = time.Now().UTC()
						if err := tx.Save(phone).Error; err != nil {
							return err
						}
					}

					if attempt.Completed {
						d := handler.GetDeployment(c)
						if err := h.service.ValidateIPCountryRestrictions(c, d.Restrictions); err != nil {
							return err
						}

						if err := tx.Create(signin).Error; err != nil {
							return err
						}

						if user != nil && user.PrimaryEmailAddressID != nil {
							var email model.UserEmailAddress
							if err := tx.Where("id = ?", *user.PrimaryEmailAddressID).First(&email).Error; err == nil {
								_ = h.service.nats.SendSignInNotificationEmail(d.ID, userID, signin.ID, email.EmailAddress)
							}
						}
					}

					if err := tx.Model(&model.Session{}).Where("id = ?", session.ID).Updates(map[string]any{
						"active_signin_id": session.ActiveSigninID,
					}).Error; err != nil {
						return err
					}

					handler.RemoveSessionFromCacheAndLocals(c, session.ID)
					return tx.Save(attempt).Error
				}); err != nil {
					return handler.SendInternalServerError(
						c,
						err,
						"Something went wrong",
					)
				}

				if attempt.Completed {
					h.service.TrackMAU(deployment.ID, userID)
				}

				h.service.DeleteOTPFromRedis(
					fmt.Sprintf("signin:%d", attempt.ID),
				)

				for i, sa := range session.SigninAttempts {
					if sa.ID == attempt.ID {
						session.SigninAttempts[i] = attempt
						break
					}
				}
			}
		case model.SignInAttemptStepVerifySecondFactor:
			if attempt.UserID == nil {
				return handler.SendBadRequest(
					c,
					nil,
					"User ID not found in sign-in attempt",
				)
			}

			var user model.User
			if err := database.Connection.Preload("UserAuthenticator").Preload("UserEmailAddresses").Where("id = ?", *attempt.UserID).First(&user).Error; err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error fetching user",
				)
			}

			method, err := h.service.Get2FAMethodFromCache(fmt.Sprintf("2fa_method:%d", attempt.ID))
			if err != nil {
				method = c.Query("method", "authenticator")
			}
			verified := false

			switch method {
			case "authenticator":
				if user.UserAuthenticator == nil || user.UserAuthenticator.TotpSecret == "" {
					return handler.SendBadRequest(
						c,
						nil,
						"Authenticator not set up",
					)
				}
				verified = totp.Validate(b.VerificationCode, user.UserAuthenticator.TotpSecret)
				if !verified {
					return handler.SendBadRequest(
						c,
						nil,
						"Invalid authentication code",
					)
				}

			case "phone_otp":
				p, err := h.service.FindUserByPhoneNumberID(*attempt.IdentifierID, deployment.ID)
				if err != nil {
					return handler.SendInternalServerError(c, err, "Error fetching user")
				}

				verified, err = h.service.VerifyPhoneOTP(deployment.ID, p.PhoneNumber, p.CountryCode, b.VerificationCode)
				if err != nil {
					return handler.SendBadRequest(c, nil, "Invalid or expired OTP")
				}

				h.service.Delete2FAMethodFromCache(fmt.Sprintf("2fa_method:%d", attempt.ID))

			case "backup_code":
				if !user.BackupCodesGenerated || len(user.BackupCodes) == 0 {
					return handler.SendBadRequest(
						c,
						nil,
						"No backup codes available",
					)
				}

				for i, code := range user.BackupCodes {
					match, err := utils.ComparePassword(code, b.VerificationCode)
					if err == nil && match {
						verified = true
						user.BackupCodes = slices.Delete(user.BackupCodes, i, i+1)
						if err := database.Connection.Model(&user).Update("backup_codes", user.BackupCodes).Error; err != nil {
							return handler.SendInternalServerError(
								c,
								err,
								"Error updating backup codes",
							)
						}
						break
					}
				}

				if !verified {
					return handler.SendBadRequest(
						c,
						nil,
						"Invalid backup code",
					)
				}

			default:
				return handler.SendBadRequest(
					c,
					nil,
					"Invalid 2FA method",
				)
			}

			if !verified {
				return handler.SendBadRequest(
					c,
					nil,
					"Invalid verification code",
				)
			}

			attempt.SecondMethodAuthenticated = true
			attempt.SecondMethodAuthenticationRequired = false

			if len(attempt.RemainingSteps) == 1 {
				attempt.Completed = true
				attempt.RemainingSteps = nil
				attempt.RemainingSteps = datatypes.JSONSlice[model.SignInAttemptStep]{}
				attempt.CurrentStep = ""
				signin = h.service.CreateSignin(user.ID, session.ID, c, deployment.AuthSettings.SessionValidityPeriod)
				session.Signins = append(session.Signins, *signin)
				session.ActiveSigninID = &signin.ID

				utils.PublishWebhookEvent(deployment.ID, "session.created", session.ID, "session")

				var primaryEmail *string
				if user.PrimaryEmailAddressID != nil {
					for _, email := range user.UserEmailAddresses {
						if email.ID == *user.PrimaryEmailAddressID {
							primaryEmail = &email.EmailAddress
							break
						}
					}
				}

				utils.PublishSignInEvent(deployment.ID, &user, "otp", primaryEmail, c)
			} else {
				attempt.RemainingSteps = attempt.RemainingSteps[1:]
				attempt.CurrentStep = attempt.RemainingSteps[0]
			}

			if err := database.Connection.Transaction(func(tx *gorm.DB) error {
				if attempt.Completed {
					d := handler.GetDeployment(c)
					if err := h.service.ValidateIPCountryRestrictions(c, d.Restrictions); err != nil {
						return err
					}

					if err := tx.Create(signin).Error; err != nil {
						return err
					}

					if err := tx.Model(&model.Session{}).Where("id = ?", session.ID).Updates(map[string]any{
						"active_signin_id": session.ActiveSigninID,
					}).Error; err != nil {
						return err
					}

					handler.RemoveSessionFromCacheAndLocals(c, session.ID)

					h.service.Delete2FAMethodFromCache(fmt.Sprintf("2fa_method:%d", attempt.ID))

					if user.PrimaryEmailAddressID != nil {
						for _, email := range user.UserEmailAddresses {
							if email.ID == *user.PrimaryEmailAddressID {
								_ = h.service.nats.SendSignInNotificationEmail(deployment.ID, user.ID, signin.ID, email.EmailAddress)
								break
							}
						}
					}
				}

				return tx.Save(attempt).Error
			}); err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error completing 2FA verification",
				)
			}

			if attempt.Completed {
				h.service.TrackMAU(deployment.ID, user.ID)
			}
		}

		for i, sa := range session.SigninAttempts {
			if sa.ID == attempt.ID {
				session.SigninAttempts[i] = attempt
				break
			}
		}
	} else {
		attempt, err := h.service.GetSignupAttempt(uint64(attemptIdentifier))
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error fetching sign up attempt")
		}

		if attempt.CurrentStep == model.SignupAttemptStepVerifyPhone {
			isValid, err := h.service.VerifyPhoneOTP(
				deployment.ID,
				attempt.PhoneNumber,
				attempt.PhoneCountryCode,
				b.VerificationCode,
			)
			if err != nil {
				return handler.SendBadRequest(c, nil, "Invalid or expired OTP")
			}
			if !isValid {
				return handler.SendBadRequest(c, nil, "Invalid OTP")
			}
		} else {
			valid, err := h.service.VerifyOTPFromRedis(fmt.Sprintf("signup:%d", attempt.ID), b.VerificationCode)
			if err != nil || !valid {
				return handler.SendBadRequest(c, nil, "Invalid or expired OTP")
			}
		}

		d := handler.GetDeployment(c)

		attempt.RemainingSteps = attempt.RemainingSteps[1:]
		if len(attempt.RemainingSteps) > 0 {
			attempt.CurrentStep = attempt.RemainingSteps[0]

			if err := database.Connection.Save(attempt).Error; err != nil {
				return handler.SendInternalServerError(c, err, "Error saving attempt")
			}

			for i, sa := range session.SignupAttempts {
				if sa.ID == attempt.ID {
					session.SignupAttempts[i] = *attempt
					break
				}
			}
		} else {
			attempt.CurrentStep = ""
			attempt.Completed = true
			user, err := h.service.CreateVerifiedUser(attempt, d)
			if err != nil {
				return handler.SendInternalServerError(c, err, "Error creating user")
			}

			if err := h.service.ValidateIPCountryRestrictions(c, d.Restrictions); err != nil {
				return handler.SendBadRequest(c, nil, err.Error(), handler.ErrCountryRestricted)
			}

			if err := database.Connection.Transaction(func(tx *gorm.DB) error {
				email := user.UserEmailAddresses[0]
				user.UserEmailAddresses = []model.UserEmailAddress{}

				email.UserID = nil

				if err := tx.Create(&email).Error; err != nil {
					return err
				}

				if err := tx.Create(user).Error; err != nil {
					return err
				}

				if err := h.service.CheckAndAddUserToOrganizationByDomain(tx, user.ID, email.EmailAddress, d.ID); err != nil {
					return err
				}

				if err := tx.Model(&model.UserEmailAddress{}).
					Where("id = ?", email.ID).
					Update("user_id", user.ID).
					Error; err != nil {
					return err
				}

				signIn := h.service.CreateSignin(user.ID, session.ID, c, d.AuthSettings.SessionValidityPeriod)

				if err := tx.Create(signIn).Error; err != nil {
					return err
				}

				if err := tx.Model(&model.Session{}).Where("id = ?", session.ID).Update("active_signin_id", signIn.ID).Error; err != nil {
					return err
				}

				if err := tx.Preload("UserEmailAddresses").First(&user, user.ID).Error; err != nil {
					return err
				}

				signIn.User = user
				session.ActiveSigninID = &signIn.ID
				session.ActiveSignin = signIn

				inviteToken := c.Query("invite_token")
				if inviteToken != "" {
					var invitation model.DeploymentInvitation
					// First check if invitation exists and is valid
					if err := tx.Where("token = ? AND deployment_id = ? AND expiry > ?",
						inviteToken, d.ID, time.Now()).
						First(&invitation).Error; err == nil {
						// Verify the email matches the invitation
						if invitation.EmailAddress == email.EmailAddress {
							// Delete the invitation as it's been accepted
							tx.Delete(&invitation)
						}
					}
				}

				return tx.Save(attempt).Error
			}); err != nil {
				return handler.SendInternalServerError(c, err, "Something went wrong")
			}

			h.service.TrackMAU(d.ID, user.ID)

			utils.PublishSignUpEvent(d.ID, user, "email_password", &attempt.Email, c)
			utils.PublishSignInEvent(d.ID, user, "email_password", &attempt.Email, c)

			handler.RemoveSessionFromCacheAndLocals(c, session.ID)

			for i, sa := range session.SignupAttempts {
				if sa.ID == attempt.ID {
					session.SignupAttempts[i] = *attempt
					break
				}
			}
		}

		if attempt.CurrentStep != model.SignupAttemptStepVerifyPhone {
			h.service.DeleteOTPFromRedis(fmt.Sprintf("signup:%d", attempt.ID))
		}
	}

	return handler.SendSuccess(c, session)
}

func (h *Handler) CompleteProfile(c *fiber.Ctx) error {
	attemptID := c.QueryInt("attempt_id")
	if attemptID == 0 {
		return handler.SendBadRequest(c, nil, "attempt_id is required")
	}

	b, validation := handler.Validate[SignUpRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	session := handler.GetSession(c)
	deployment := handler.GetDeployment(c)

	// Try to find a signin attempt first
	var signinAttempt model.SignInAttempt
	signinErr := database.Connection.Where("id = ? AND session_id = ? AND requires_completion = true", attemptID, session.ID).
		First(&signinAttempt).
		Error

	if signinErr == nil {
		return h.handleSigninProfileCompletion(c, &signinAttempt, b, session, deployment)
	}

	// Try to find an OAuth signup attempt
	var signupAttempt model.SignupAttempt
	signupErr := database.Connection.Where("id = ? AND session_id = ? AND is_oauth_signup = true", attemptID, session.ID).
		First(&signupAttempt).
		Error

	if signupErr == nil {
		return h.handleOAuthSignupCompletion(c, &signupAttempt, b, session, deployment)
	}

	return handler.SendBadRequest(c, nil, "Invalid attempt ID or attempt not found")
}

func (h *Handler) CompleteOAuthSignup(c *fiber.Ctx) error {
	attemptID := c.QueryInt("attempt_id")
	if attemptID == 0 {
		return handler.SendBadRequest(c, nil, "attempt_id is required")
	}

	b, validation := handler.Validate[SignUpRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	session := handler.GetSession(c)
	deployment := handler.GetDeployment(c)

	var attempt model.SignupAttempt
	if err := database.Connection.Where("id = ? AND session_id = ? AND is_oauth_signup = true", attemptID, session.ID).First(&attempt).Error; err != nil {
		return handler.SendBadRequest(c, nil, "Invalid OAuth signup attempt")
	}

	if b.FirstName != "" {
		attempt.FirstName = b.FirstName
	}
	if b.LastName != "" {
		attempt.LastName = b.LastName
	}
	if b.Username != "" {
		attempt.Username = b.Username
	}
	if b.PhoneNumber != "" {
		attempt.PhoneNumber = b.PhoneNumber
		attempt.PhoneCountryCode = b.PhoneCountryCode
	}

	err := h.service.ValidateSignUpRequest(b, deployment)
	if err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	data := model.ProfileCompletionData{
		FirstName:        attempt.FirstName,
		LastName:         attempt.LastName,
		Username:         attempt.Username,
		Email:            attempt.Email,
		PhoneNumber:      attempt.PhoneNumber,
		PhoneCountryCode: attempt.PhoneCountryCode,
	}

	missingFields := h.service.CheckMissingFieldsFromData(data, deployment.AuthSettings)

	if len(missingFields) > 0 {
		attempt.MissingFields = datatypes.NewJSONSlice(missingFields)
		database.Connection.Save(&attempt)
		return handler.SendBadRequest(c, nil, "Missing required fields")
	}

	attempt.MissingFields = datatypes.NewJSONSlice([]string{})

	if attempt.PhoneNumber != "" && deployment.AuthSettings.PhoneNumber.VerifySignup {
		steps := []model.SignupAttemptStep(attempt.RemainingSteps)
		steps = append(steps, model.SignupAttemptStepVerifyPhone)
		attempt.RemainingSteps = datatypes.NewJSONSlice(steps)
		if attempt.CurrentStep == "" {
			attempt.CurrentStep = model.SignupAttemptStepVerifyPhone
		}
	}

	if len(attempt.RemainingSteps) == 0 {
		user, err := h.service.CreateOAuthUser(&attempt, deployment)
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error creating user")
		}

		if err := h.service.ValidateIPCountryRestrictions(c, deployment.Restrictions); err != nil {
			return handler.SendBadRequest(c, nil, err.Error(), handler.ErrCountryRestricted)
		}

		signIn := h.service.CreateSignin(user.ID, session.ID, c, deployment.AuthSettings.SessionValidityPeriod)
		signIn.User = user

		err = database.Connection.Transaction(func(tx *gorm.DB) error {
			if err := tx.Create(user).Error; err != nil {
				return err
			}

			if err := tx.Create(signIn).Error; err != nil {
				return err
			}

			return tx.Model(&model.Session{}).Where("id = ?", session.ID).Update("active_signin_id", signIn.ID).Error
		})
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error completing signup")
		}

		h.service.TrackMAU(deployment.ID, user.ID)

		handler.RemoveSessionFromCacheAndLocals(c, session.ID)
		return handler.SendSuccess(c, session)
	}

	if err := database.Connection.Save(&attempt).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Error saving attempt")
	}

	return handler.SendSuccess(c, fiber.Map{
		"signup_attempt": attempt,
		"session":        session,
	})
}

func (h *Handler) CompleteSignInProfile(c *fiber.Ctx) error {
	attemptID := c.QueryInt("attempt_id")
	if attemptID == 0 {
		return handler.SendBadRequest(c, nil, "attempt_id is required")
	}

	b, validation := handler.Validate[SignUpRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	session := handler.GetSession(c)
	deployment := handler.GetDeployment(c)

	var attempt model.SignInAttempt
	if err := database.Connection.Where("id = ? AND session_id = ? AND requires_completion = true", attemptID, session.ID).First(&attempt).Error; err != nil {
		return handler.SendBadRequest(c, nil, "Invalid signin attempt")
	}

	var user model.User
	if err := database.Connection.Where("id = ?", attempt.UserID).First(&user).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Error finding user")
	}

	if b.FirstName != "" {
		user.FirstName = b.FirstName
	}
	if b.LastName != "" {
		user.LastName = b.LastName
	}
	if b.Username != "" {
		user.Username = b.Username
	}

	if b.PhoneNumber != "" {
		if err := h.service.ValidatePhoneRestrictions(b.PhoneNumber, b.PhoneCountryCode, deployment.Restrictions); err != nil {
			return handler.SendBadRequest(c, nil, err.Error())
		}

		phoneID := snowflake.ID()
		phone := model.UserPhoneNumber{
			Model:        model.Model{ID: phoneID},
			PhoneNumber:  b.PhoneNumber,
			CountryCode:  b.PhoneCountryCode,
			Verified:     false,
			DeploymentID: deployment.ID,
			UserID:       user.ID,
		}

		if err := database.Connection.Create(&phone).Error; err != nil {
			return handler.SendInternalServerError(c, err, "Error creating phone number")
		}

		user.PrimaryPhoneNumberID = &phoneID
	}

	missingFields := h.service.CheckMissingRequiredFields(&user, deployment.AuthSettings)
	if len(missingFields) > 0 {
		attempt.MissingFields = datatypes.NewJSONSlice(missingFields)
		database.Connection.Save(&attempt)
		return handler.SendBadRequest(c, nil, "Missing required fields")
	}

	attempt.RequiresCompletion = false
	attempt.MissingFields = datatypes.NewJSONSlice([]string{})

	if b.PhoneNumber != "" && deployment.AuthSettings.PhoneNumber.VerifySignup {
		steps := []model.SignInAttemptStep(attempt.RemainingSteps)
		steps = append(steps, model.SignInAttemptStepVerifyPhone)
		attempt.RemainingSteps = datatypes.NewJSONSlice(steps)
		if attempt.CurrentStep == "" {
			attempt.CurrentStep = model.SignInAttemptStepVerifyPhone
		}
	}

	if len(attempt.RemainingSteps) == 0 {
		if err := h.service.ValidateIPCountryRestrictions(c, deployment.Restrictions); err != nil {
			return handler.SendBadRequest(c, nil, err.Error(), handler.ErrCountryRestricted)
		}

		signIn := h.service.CreateSignin(user.ID, session.ID, c, deployment.AuthSettings.SessionValidityPeriod)

		err := database.Connection.Transaction(func(tx *gorm.DB) error {
			if err := tx.Save(&user).Error; err != nil {
				return err
			}

			if err := tx.Create(signIn).Error; err != nil {
				return err
			}

			attempt.Completed = true
			if err := tx.Save(&attempt).Error; err != nil {
				return err
			}

			if user.PrimaryEmailAddressID != nil {
				for _, email := range user.UserEmailAddresses {
					if email.ID == *user.PrimaryEmailAddressID {
						_ = h.service.nats.SendSignInNotificationEmail(
							deployment.ID,
							user.ID,
							signIn.ID,
							email.EmailAddress,
						)
						break
					}
				}
			}

			return tx.Model(&model.Session{}).Where("id = ?", session.ID).Update("active_signin_id", signIn.ID).Error
		})
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error completing signin")
		}

		h.service.TrackMAU(deployment.ID, user.ID)

		handler.RemoveSessionFromCacheAndLocals(c, session.ID)
		return handler.SendSuccess(c, session)
	}

	if err := database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(&user).Error; err != nil {
			return err
		}
		return tx.Save(attempt).Error
	}); err != nil {
		return handler.SendInternalServerError(c, err, "Error saving attempt")
	}

	session.SigninAttempts = append(session.SigninAttempts, attempt)
	handler.RemoveSessionFromCacheAndLocals(c, session.ID)
	return handler.SendSuccess(c, session)
}

func (h *Handler) ForgotPassword(c *fiber.Ctx) error {
	b, validation := handler.Validate[ForgotPasswordRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	d := handler.GetDeployment(c)

	email, err := h.service.FindUserByEmail(b.Email, d.ID)
	if err != nil {
		if err == handler.ErrUserNotFound {
			return handler.SendNotFound(
				c,
				nil,
				err.Error(),
				handler.ErrUserNotFound,
			)
		}
		return handler.SendInternalServerError(
			c,
			err,
			"Something went wrong",
		)
	}

	if err = h.service.ValidateUserStatus(email); err != nil {
		return handler.SendForbidden(
			c,
			nil,
			err.Error(),
			handler.ErrUserDisabled,
		)
	}

	if b.OTP != "" {
		valid, err := h.service.VerifyOTPFromRedis(fmt.Sprintf("password-reset:%d", *email.UserID), b.OTP)
		if err != nil || !valid {
			return handler.SendBadRequest(
				c,
				nil,
				"Invalid or expired OTP",
			)
		}

		token, err := utils.GenerateSecureToken(32)
		if err != nil {
			return handler.SendInternalServerError(
				c,
				err,
				"Error generating token",
			)
		}

		if err := h.service.StoreResetTokenInCache(token, *email.UserID); err != nil {
			return handler.SendInternalServerError(
				c,
				err,
				"Error storing token",
			)
		}

		h.service.DeleteOTPFromRedis(fmt.Sprintf("password-reset:%d", *email.UserID))

		return handler.SendSuccess(c, fiber.Map{
			"token": token,
		})
	}

	code, err := utils.GenerateOTP()
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Error generating OTP",
			handler.ErrInternal,
		)
	}

	if err := h.service.StoreOTPInCache(fmt.Sprintf("password-reset:%d", *email.UserID), code); err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Error storing OTP",
			handler.ErrInternal,
		)
	}

	if err := h.service.SendPasswordResetEmail(&d, *email.UserID, email.EmailAddress, code, c.IP(), c.Get("User-Agent")); err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Error sending password reset email",
		)
	}

	return handler.SendSuccess[any](c, nil)
}

func (h *Handler) ResetPassword(c *fiber.Ctx) error {
	b, validation := handler.Validate[ResetPasswordRequest](c)
	deployment := handler.GetDeployment(c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	if err := h.service.ValidatePasswordWithSettings(b.Password, deployment.AuthSettings.Password); err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	userID, err := h.service.GetUserIDFromResetToken(b.Token)
	if err != nil {
		return handler.SendBadRequest(
			c,
			nil,
			"Invalid or expired token",
		)
	}

	var user model.User
	if err := database.Connection.Preload("UserEmailAddresses").Where("id = ?", userID).First(&user).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Error finding user",
		)
	}

	hashedPassword, err := h.service.HashPassword(b.Password)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Error hashing password",
		)
	}

	if err := database.Connection.Model(&user).Update("password", hashedPassword).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Error updating password",
		)
	}

	h.service.DeleteResetTokenFromCache(b.Token)

	// Send password change notification email
	if user.PrimaryEmailAddressID != nil {
		for _, email := range user.UserEmailAddresses {
			if email.ID == *user.PrimaryEmailAddressID {
				_ = h.service.nats.SendPasswordChangeEmail(deployment.ID, user.ID, email.EmailAddress)
				break
			}
		}
	}

	utils.PublishWebhookEvent(deployment.ID, "user.password.reset", userID, "user")

	session := handler.GetSession(c)

	secondFactorEnforced := user.SecondFactorPolicy == model.SecondFactorPolicyEnforced
	missingFields := h.service.CheckMissingRequiredFields(&user, deployment.AuthSettings)
	requiresCompletion := len(missingFields) > 0

	var steps []model.SignInAttemptStep

	if secondFactorEnforced {
		steps = append(steps, model.SignInAttemptStepVerifySecondFactor)
	}

	if requiresCompletion {
		steps = append(steps, model.SignInAttemptStepCompleteProfile)
	}

	authenticated := true
	completed := len(steps) == 0

	attempt := h.service.CreateSignInAttempt(
		&user.ID,
		nil,
		session.ID,
		model.SignInMethodPlainEmail,
		steps,
		completed,
		&deployment,
	)

	attempt.FirstMethodAuthenticated = authenticated

	if requiresCompletion {
		attempt.RequiresCompletion = true
		attempt.MissingFields = datatypes.NewJSONSlice(missingFields)
		requiredFields := h.service.GetRequiredFields(deployment.AuthSettings)
		attempt.RequiredFields = datatypes.NewJSONSlice(requiredFields)
		completed = false
	}

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(attempt).Error; err != nil {
			return err
		}

		if completed {
			if err := h.service.ValidateIPCountryRestrictions(c, deployment.Restrictions); err != nil {
				return err
			}

			signIn := h.service.CreateSignin(user.ID, session.ID, c, deployment.AuthSettings.SessionValidityPeriod)
			if err := tx.Create(signIn).Error; err != nil {
				return err
			}

			if err := tx.Model(&model.Session{}).Where("id = ?", session.ID).Update("active_signin_id", signIn.ID).Error; err != nil {
				return err
			}

			if user.PrimaryEmailAddressID != nil {
				for _, email := range user.UserEmailAddresses {
					if email.ID == *user.PrimaryEmailAddressID {
						_ = h.service.nats.SendSignInNotificationEmail(
							deployment.ID,
							user.ID,
							signIn.ID,
							email.EmailAddress,
						)
						break
					}
				}
			}

			utils.PublishSignInEvent(deployment.ID, &user, "password_reset", nil, c)
		}

		return nil
	})

	if err != nil {
		return handler.SendInternalServerError(c, err, "Error processing signin")
	}

	if completed {
		h.service.TrackMAU(deployment.ID, user.ID)
	}

	session.SigninAttempts = append(session.SigninAttempts, *attempt)
	handler.RemoveSessionFromCacheAndLocals(c, session.ID)
	return handler.SendSuccess(c, session)
}

func (h *Handler) handleOAuthSignupCompletion(
	c *fiber.Ctx,
	attempt *model.SignupAttempt,
	b *SignUpRequest,
	session *model.Session,
	deployment model.Deployment,
) error {
	if b.FirstName != "" {
		attempt.FirstName = b.FirstName
	}
	if b.LastName != "" {
		attempt.LastName = b.LastName
	}
	if b.Username != "" {
		attempt.Username = b.Username
	}
	if b.PhoneNumber != "" {
		attempt.PhoneNumber = b.PhoneNumber
		attempt.PhoneCountryCode = b.PhoneCountryCode
	}

	err := h.service.ValidateSignUpRequest(b, deployment)
	if err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	data := model.ProfileCompletionData{
		FirstName:        attempt.FirstName,
		LastName:         attempt.LastName,
		Username:         attempt.Username,
		Email:            attempt.Email,
		PhoneNumber:      attempt.PhoneNumber,
		PhoneCountryCode: attempt.PhoneCountryCode,
	}

	missingFields := h.service.CheckMissingFieldsFromData(data, deployment.AuthSettings)

	if len(missingFields) > 0 {
		attempt.MissingFields = datatypes.NewJSONSlice(missingFields)
		database.Connection.Save(attempt)
		return handler.SendBadRequest(c, nil, "Missing required fields")
	}

	attempt.MissingFields = datatypes.NewJSONSlice([]string{})

	verificationSteps := h.service.DetermineVerificationStepsForProfileCompletion(data, nil, deployment.AuthSettings)

	// Convert string steps to SignupAttemptStep and add to existing steps
	steps := []model.SignupAttemptStep(attempt.RemainingSteps)
	for _, step := range verificationSteps {
		switch step {
		case "verify_email":
			steps = append(steps, model.SignupAttemptStepVerifyEmail)
		case "verify_phone":
			steps = append(steps, model.SignupAttemptStepVerifyPhone)
		}
	}

	if len(steps) > len(attempt.RemainingSteps) {
		attempt.RemainingSteps = datatypes.NewJSONSlice(steps)
		if attempt.CurrentStep == "" && len(steps) > 0 {
			attempt.CurrentStep = steps[0]
		}
	}

	if len(attempt.RemainingSteps) == 0 {
		user, err := h.service.CreateOAuthUser(attempt, deployment)
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error creating user")
		}

		if err := h.service.ValidateIPCountryRestrictions(c, deployment.Restrictions); err != nil {
			return handler.SendBadRequest(c, nil, err.Error(), handler.ErrCountryRestricted)
		}

		signIn := h.service.CreateSignin(user.ID, session.ID, c, deployment.AuthSettings.SessionValidityPeriod)
		signIn.User = user

		err = database.Connection.Transaction(func(tx *gorm.DB) error {
			if err := tx.Create(user).Error; err != nil {
				return err
			}

			if err := tx.Create(signIn).Error; err != nil {
				return err
			}

			return tx.Model(&model.Session{}).Where("id = ?", session.ID).Update("active_signin_id", signIn.ID).Error
		})
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error completing signup")
		}

		handler.RemoveSessionFromCacheAndLocals(c, session.ID)
		return handler.SendSuccess(c, session)
	}

	if err := database.Connection.Save(attempt).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Error saving attempt")
	}

	return handler.SendSuccess(c, fiber.Map{
		"signup_attempt": *attempt,
		"session":        *session,
	})
}

func (h *Handler) handleSigninProfileCompletion(
	c *fiber.Ctx,
	attempt *model.SignInAttempt,
	b *SignUpRequest,
	session *model.Session,
	deployment model.Deployment,
) error {
	var user model.User
	if err := database.Connection.Where("id = ?", attempt.UserID).First(&user).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Error finding user")
	}

	if b.FirstName != "" {
		user.FirstName = b.FirstName
	}
	if b.LastName != "" {
		user.LastName = b.LastName
	}
	if b.Username != "" {
		user.Username = b.Username
	}

	attempt.ProfileCompletionData = &model.ProfileCompletionData{
		FirstName:        b.FirstName,
		LastName:         b.LastName,
		Username:         b.Username,
		Email:            b.Email,
		PhoneNumber:      b.PhoneNumber,
		PhoneCountryCode: b.PhoneCountryCode,
	}

	if b.PhoneNumber != "" {
		if err := h.service.ValidatePhoneRestrictions(b.PhoneNumber, b.PhoneCountryCode, deployment.Restrictions); err != nil {
			return handler.SendBadRequest(c, nil, err.Error())
		}
	}

	missingFields := h.service.CheckMissingRequiredFields(&user, deployment.AuthSettings)
	if len(missingFields) > 0 {
		attempt.MissingFields = datatypes.NewJSONSlice(missingFields)
		database.Connection.Save(attempt)
		return handler.SendBadRequest(c, nil, "Missing required fields")
	}

	attempt.RequiresCompletion = false
	attempt.MissingFields = datatypes.NewJSONSlice([]string{})

	verificationSteps := h.service.DetermineVerificationStepsForProfileCompletion(
		*attempt.ProfileCompletionData,
		&user.ID,
		deployment.AuthSettings,
	)

	steps := []model.SignInAttemptStep(attempt.RemainingSteps)
	for _, step := range verificationSteps {
		switch step {
		case "verify_email":
			steps = append(steps, model.SignInAttemptStepVerifyEmailOTP)
		case "verify_phone":
			steps = append(steps, model.SignInAttemptStepVerifyPhoneOTP)
		}
	}

	if len(steps) > len(attempt.RemainingSteps) {
		attempt.RemainingSteps = datatypes.NewJSONSlice(steps)
		if attempt.CurrentStep == "" && len(steps) > 0 {
			attempt.CurrentStep = steps[0]
		}
	} else if attempt.CurrentStep == model.SignInAttemptStepCompleteProfile {

		if len(attempt.RemainingSteps) > 1 {
			attempt.RemainingSteps = attempt.RemainingSteps[1:]
			attempt.CurrentStep = attempt.RemainingSteps[0]
		} else {

			attempt.RemainingSteps = nil
			attempt.CurrentStep = ""
		}
	}

	if len(attempt.RemainingSteps) == 0 {
		if err := h.service.ValidateIPCountryRestrictions(c, deployment.Restrictions); err != nil {
			return handler.SendBadRequest(c, nil, err.Error(), handler.ErrCountryRestricted)
		}

		signIn := h.service.CreateSignin(user.ID, session.ID, c, deployment.AuthSettings.SessionValidityPeriod)

		err := database.Connection.Transaction(func(tx *gorm.DB) error {
			if err := tx.Save(&user).Error; err != nil {
				return err
			}

			if err := tx.Create(signIn).Error; err != nil {
				return err
			}

			attempt.Completed = true
			if err := tx.Save(attempt).Error; err != nil {
				return err
			}

			if user.PrimaryEmailAddressID != nil {
				for _, email := range user.UserEmailAddresses {
					if email.ID == *user.PrimaryEmailAddressID {
						_ = h.service.nats.SendSignInNotificationEmail(
							deployment.ID,
							user.ID,
							signIn.ID,
							email.EmailAddress,
						)
						break
					}
				}
			}

			return tx.Model(&model.Session{}).Where("id = ?", session.ID).Update("active_signin_id", signIn.ID).Error
		})
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error completing signin")
		}

		h.service.TrackMAU(deployment.ID, user.ID)

		handler.RemoveSessionFromCacheAndLocals(c, session.ID)
		return handler.SendSuccess(c, session)
	}

	if err := database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(&user).Error; err != nil {
			return err
		}
		return tx.Save(attempt).Error
	}); err != nil {
		return handler.SendInternalServerError(c, err, "Error saving attempt")
	}

	return handler.SendSuccess(c, fiber.Map{
		"signin_attempt": *attempt,
		"session":        *session,
	})
}
