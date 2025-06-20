package auth

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

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
	default:
		return handler.SendBadRequest(c, nil, "Invalid or missing strategy")
	}
}

func (h *Handler) handleUsernameSignIn(c *fiber.Ctx, b SignInRequest, d model.Deployment, session *model.Session) error {
	user, err := h.service.FindUserByUsername(b.Username)
	if err != nil {
		if err == handler.ErrUserNotFound {
			return handler.SendUnauthorized(c, nil, "Invalid credentials", handler.ErrInvalidCredentials)
		}
		return handler.SendInternalServerError(
			c,
			err,
			"Something went wrong",
		)
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

	secondFactorEnforced := user.SecondFactorPolicy == model.SecondFactorPolicyEnforced

	steps, completed := h.service.DetermineAuthenticationStep(
		true,
		authenticated,
		secondFactorEnforced,
		d.AuthSettings,
	)

	attempt := h.service.CreateSignInAttempt(
		&user.ID,
		nil,
		session.ID,
		model.SignInMethodPlainUsername,
		steps,
		completed,
	)

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

			signIn := model.NewSignIn(session.ID, user.ID)
			if err := tx.Create(signIn).Error; err != nil {
				return err
			}

			if err := tx.Model(&session).Update("active_signin_id", signIn.ID).Error; err != nil {
				return err
			}
		}

		return nil
	})

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
	handler.RemoveSessionFromCache(session.ID)
	return handler.SendSuccess(c, session)
}

func (h *Handler) handleEmailPasswordSignIn(c *fiber.Ctx, b SignInRequest, d model.Deployment, session *model.Session) error {
	email, err := h.service.FindUserByEmail(b.Email)
	if err != nil {
		if err == handler.ErrUserNotFound {
			return handler.SendUnauthorized(c, nil, "Invalid credentials", handler.ErrInvalidCredentials)
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

	secondFactorEnforced := email.User.SecondFactorPolicy == model.SecondFactorPolicyEnforced

	steps, completed := h.service.DetermineAuthenticationStep(
		email.Verified,
		authenticated,
		secondFactorEnforced,
		d.AuthSettings,
	)

	attempt := h.service.CreateSignInAttempt(
		email.UserID,
		&email.ID,
		session.ID,
		model.SignInMethodPlainEmail,
		steps,
		completed,
	)

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

			signIn := model.NewSignIn(session.ID, email.User.ID)
			if err := tx.Create(signIn).Error; err != nil {
				return err
			}

			if err := tx.Model(&session).Update("active_signin_id", signIn.ID).Error; err != nil {
				return err
			}
		}

		return nil
	})

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
	handler.RemoveSessionFromCache(session.ID)
	return handler.SendSuccess(c, session)
}

func (h *Handler) handleOTPSignIn(c *fiber.Ctx, b SignInRequest, session *model.Session, method model.SignInMethod) error {
	var userID uint64
	var identifierID uint64

	if method == model.SignInMethodEmailOTP {
		email, err := h.service.FindUserByEmail(b.Email)

		if email != nil {
			userID = *email.UserID
			identifierID = email.ID

			if err = h.service.ValidateUserStatus(email); err != nil {
				return handler.SendForbidden(c, nil, err.Error(), handler.ErrUserDisabled)
			}
		}
	} else if method == model.SignInMethodPhoneOTP {
		phone, err := h.service.FindUserByPhoneNumber(b.Phone)

		if phone != nil {
			userID = phone.User.ID
			identifierID = phone.ID

			if err = h.service.ValidatePhoneUserStatus(phone); err != nil {
				return handler.SendForbidden(c, nil, err.Error(), handler.ErrUserDisabled)
			}
		}
	}

	steps := []model.SignInAttemptStep{model.SignInAttemptStepVerifyEmailOTP}
	if method == model.SignInMethodPhoneOTP {
		steps = []model.SignInAttemptStep{model.SignInAttemptStepVerifyPhoneOTP}
	}

	attempt := h.service.CreateSignInAttempt(
		&userID,
		&identifierID,
		session.ID,
		method,
		steps,
		false,
	)

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
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	session.SigninAttempts = append(session.SigninAttempts, *attempt)
	handler.RemoveSessionFromCache(session.ID)
	return handler.SendSuccess(c, session)
}

func (h *Handler) handleMagicLinkSignIn(c *fiber.Ctx, b SignInRequest, d model.Deployment, session *model.Session) error {
	email, _ := h.service.FindUserByEmail(b.Email)
	steps := []model.SignInAttemptStep{model.SignInAttemptStepVerifyEmailLink}
	requiresCompletion := false
	missingFields := []string{}
	var attempt *model.SignInAttempt

	if email != nil {
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

		attempt = h.service.CreateSignInAttempt(
			email.UserID,
			&email.ID,
			session.ID,
			model.SignInMethodMagicLink,
			steps,
			false,
		)
	} else {
		attempt = h.service.CreateSignInAttempt(
			nil,
			nil,
			session.ID,
			model.SignInMethodMagicLink,
			steps,
			false,
		)
	}

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
	handler.RemoveSessionFromCache(session.ID)
	return handler.SendSuccess(c, session)
}

func (h *Handler) SignUp(c *fiber.Ctx) error {
	b, validation := handler.Validate[SignUpRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	if err := h.service.ValidatePassword(b.Password); err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	d := handler.GetDeployment(c)
	session := handler.GetSession(c)

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

	var errors []handler.Error

	if b.Email != "" && h.service.CheckEmailExists(b.Email) {
		errors = append(errors, handler.ErrEmailExists)
	}

	if b.Username != "" && h.service.CheckUsernameExists(b.Username) {
		errors = append(errors, handler.ErrUsernameExists)
	}

	if b.PhoneNumber != "" &&
		h.service.CheckUserphoneExists(b.PhoneNumber) {
		errors = append(errors, handler.ErrPhoneNumberExists)
	}

	if len(errors) > 0 {
		return handler.SendBadRequest(
			c,
			nil,
			"Field errors",
			errors...)
	}

	hashedPassword, err := h.service.HashPassword(b.Password)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Error hashing password",
		)
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
				!d.AuthSettings.VerificationPolicy.Email,
			)

			if err := tx.Create(&u).Error; err != nil {
				return err
			}

			if err := h.service.ValidateIPCountryRestrictions(c, d.Restrictions); err != nil {
				return err
			}

			signIn := model.NewSignIn(session.ID, u.ID)
			signIn.User = &u

			if err := tx.Create(signIn).Error; err != nil {
				return err
			}

			if err := tx.Model(&session).Update("active_signin_id", signIn.ID).Error; err != nil {
				return err
			}
		}

		handler.RemoveSessionFromCache(session.ID)

		return nil
	})
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Something went wrong",
		)
	}

	return handler.SendSuccess(c, session)
}

func (h *Handler) AuthMethods(c *fiber.Ctx) error {
	d := handler.GetDeployment(c)
	return handler.SendSuccess(c, d.AuthSettings)
}

func (h *Handler) InitSSO(c *fiber.Ctx) error {
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

	customRedirectURI := c.Query("redirect_uri")

	url, err := utils.GenerateVerificationUrlForDeployment(provider, *attempt, &deployment, customRedirectURI)
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

func (h *Handler) SSOCallback(c *fiber.Ctx) error {
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
	stateParts := strings.Split(state, ":")
	attemptID := stateParts[0]
	var customRedirectURI string
	if len(stateParts) > 1 {
		customRedirectURI = stateParts[1]
	}

	var attempt model.SignInAttempt
	if err := database.Connection.Where("id = ?", attemptID).First(&attempt).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to find sign in attempt",
			handler.ErrInvalidState,
		)
	}

	conf, err := utils.GetOAuthConfigForDeployment(attempt.SSOProvider, &deployment, customRedirectURI)
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
			"Failed to exchange code for token",
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

	var email model.UserEmailAddress
	exists := database.Connection.Joins(
		"User",
		database.Connection.Where(
			&model.User{DeploymentID: deployment.ID},
		),
	).Preload("User.SocialConnections").
		Where("email = ?", user.Email).First(&email).RowsAffected > 0

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
				deployment.AuthSettings,
			)
			if err != nil {
				return err
			}

			if signIn != nil {
				session.Signins = append(session.Signins, *signIn)
				session.ActiveSigninID = &signIn.ID
			}

			attempt.Completed = true
			if err := tx.Save(&attempt).Error; err != nil {
				return err
			}

			return nil
		}

		if err != nil {
			return err
		}

		primaryAddressID := snowflake.ID()

		u := model.User{
			Model: model.Model{
				ID: snowflake.ID(),
			},
			SchemaVersion:         model.SchemaVersionV1,
			SecondFactorPolicy:    deployment.AuthSettings.SecondFactorPolicy,
			DeploymentID:          deployment.ID,
			PrimaryEmailAddressID: &primaryAddressID,
		}

		if err := tx.Create(&u).Error; err != nil {
			return err
		}

		email := model.UserEmailAddress{
			Model:        model.Model{ID: primaryAddressID},
			EmailAddress: user.Email,
			IsPrimary:    true,
			UserID:       &u.ID,
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

		signIn := model.NewSignIn(session.ID, u.ID)

		if err := tx.Create(&connection).Error; err != nil {
			return err
		}

		if err := tx.Create(&signIn).Error; err != nil {
			return err
		}

		session.Signins = append(session.Signins, *signIn)
		session.ActiveSigninID = &signIn.ID

		attempt.Completed = true
		if err := tx.Save(&attempt).Error; err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Something went wrong",
		)
	}

	if err := database.Connection.Model(&model.Session{}).Where("id = ?", session.ID).Updates(map[string]interface{}{
		"active_signin_id": session.ActiveSigninID,
	}).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to save session",
		)
	}

	handler.RemoveSessionFromCache(session.ID)

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
	exists, err := h.service.CheckIdentifierAvailability(
		identifier,
		identifierType,
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
			if attempt.IdentifierID == nil {
				return handler.SendSuccess[any](c, nil)
			}

			email, err := h.service.FindUserByEmailID(
				*attempt.IdentifierID,
			)
			if err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error fetching user",
					handler.ErrInvalidSignInAttempt,
				)
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

			if err := h.service.StoreOTPInCache(fmt.Sprintf("signin:%d", attempt.ID), code); err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error storing OTP",
					handler.ErrInternal,
				)
			}

			if err := h.service.SendEmailOTPVerificationAsync(email.EmailAddress, deployment); err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error sending email OTP verification",
				)
			}
		case model.SignInAttemptStepVerifyPhoneOTP:
			if attempt.IdentifierID == nil {
				return handler.SendSuccess[any](c, nil)
			}

			phone, err := h.service.FindUserByPhoneNumberID(
				*attempt.IdentifierID,
			)
			if err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error fetching user",
					handler.ErrInvalidSignInAttempt,
				)
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

			if err := h.service.StoreOTPInCache(fmt.Sprintf("signin:%d", attempt.ID), code); err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error storing OTP",
					handler.ErrInternal,
				)
			}

			if err := h.service.SendSmsOTPVerificationAsync(phone.PhoneNumber, deployment); err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error sending SMS OTP verification",
				)
			}
		case model.SignInAttemptStepVerifyEmailLink:
			if attempt.IdentifierID == nil {
				return handler.SendSuccess[any](c, nil)
			}

			email, err := h.service.FindUserByEmailID(
				*attempt.IdentifierID,
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

			if err := h.service.SendEmailOTPVerificationAsync(attempt.Email, deployment); err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error sending email OTP verification",
				)
			}
		case model.SignupAttemptStepVerifyPhone:
			code, err := utils.GenerateOTP()
			if err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error generating OTP",
					handler.ErrInternal,
				)
			}

			if err := h.service.StoreOTPInCache(fmt.Sprintf("signin:%d", attempt.ID), code); err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error storing OTP",
					handler.ErrInternal,
				)
			}

			if err := h.service.SendSmsOTPVerificationAsync(attempt.PhoneNumber, deployment); err != nil {
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
	redirectURI := c.Query("redirect_uri")

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

	if attempt.IdentifierID == nil {
		return handler.SendBadRequest(c, nil, "Invalid or expired magic link")
	}

	email, err := h.service.FindUserByEmailID(*attempt.IdentifierID)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Error fetching user")
	}

	if len(attempt.RemainingSteps) == 1 {
		attempt.Completed = true
		attempt.RemainingSteps = nil

		if err := h.service.ValidateIPCountryRestrictions(c, deployment.Restrictions); err != nil {
			return handler.SendBadRequest(c, nil, err.Error(), handler.ErrCountryRestricted)
		}

		signIn := model.NewSignIn(session.ID, email.User.ID)
		signIn.User = &email.User

		err = database.Connection.Transaction(func(tx *gorm.DB) error {
			if err := tx.Create(signIn).Error; err != nil {
				return err
			}

			if err := tx.Model(&session).Update("active_signin_id", signIn.ID).Error; err != nil {
				return err
			}

			return tx.Save(&attempt).Error
		})

		if err != nil {
			return handler.SendInternalServerError(c, err, "Error completing signin")
		}

		handler.RemoveSessionFromCache(session.ID)

		// Use custom redirect URI if provided, otherwise default to signin page
		var redirectURL string
		if redirectURI != "" {
			// Parse and validate the redirect URI
			parsedURL, err := url.Parse(redirectURI)
			if err != nil {
				redirectURL = fmt.Sprintf("https://%s/auth/signin?magic_link=verified", deployment.FrontendHost)
			} else {
				// Add magic_link=verified parameter to the redirect URI
				query := parsedURL.Query()
				query.Set("magic_link", "verified")
				parsedURL.RawQuery = query.Encode()
				redirectURL = parsedURL.String()
			}
		} else {
			redirectURL = fmt.Sprintf("https://%s/auth/signin?magic_link=verified", deployment.FrontendHost)
		}

		return c.Redirect(redirectURL)
	} else {
		attempt.RemainingSteps = attempt.RemainingSteps[1:]
		attempt.CurrentStep = attempt.RemainingSteps[0]

		if err := database.Connection.Save(&attempt).Error; err != nil {
			return handler.SendInternalServerError(c, err, "Error updating attempt")
		}

		var redirectURL string
		if redirectURI != "" {
			parsedURL, err := url.Parse(redirectURI)
			if err != nil {
				redirectURL = fmt.Sprintf("https://%s/auth/signin?magic_link=verified&continue=true", deployment.FrontendHost)
			} else {
				query := parsedURL.Query()
				query.Set("magic_link", "verified")
				query.Set("continue", "true")
				parsedURL.RawQuery = query.Encode()
				redirectURL = parsedURL.String()
			}
		} else {
			redirectURL = fmt.Sprintf("https://%s/auth/signin?magic_link=verified&continue=true", deployment.FrontendHost)
		}

		return c.Redirect(redirectURL)
	}
}

func (h *Handler) AttemptVerification(c *fiber.Ctx) error {
	attemptIdentifier := c.QueryInt("attempt_identifier")
	identifierType := c.Query("identifier_type")
	session := handler.GetSession(c)

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
				if attempt.IdentifierID != nil {
					return handler.SendBadRequest(
						c,
						nil,
						"Invalid or expired OTP",
					)
				}

				email, err := h.service.FindUserByEmailID(
					*attempt.IdentifierID,
				)
				if err != nil {
					return handler.SendInternalServerError(
						c,
						err,
						"Error fetching user",
					)
				}
				if attempt.CurrentStep == model.SignInAttemptStepVerifyEmailOTP &&
					email.Verified {
					return handler.SendBadRequest(
						c,
						nil,
						"Email already verified",
					)
				}

				storedOTP, err := h.service.GetOTPFromRedis(
					fmt.Sprintf("signin:%d", attempt.ID),
				)
				if err != nil {
					return handler.SendBadRequest(
						c,
						nil,
						"Invalid or expired OTP",
					)
				}

				if storedOTP != b.VerificationCode {
					return handler.SendBadRequest(
						c,
						nil,
						"Invalid OTP",
					)
				}

				if len(attempt.RemainingSteps) == 1 {
					attempt.Completed = true
					attempt.RemainingSteps = nil
					signin = model.NewSignIn(session.ID, *email.UserID)
					signin.User = &email.User

					session.Signins = append(session.Signins, *signin)
					session.ActiveSigninID = &signin.ID
				} else {
					attempt.RemainingSteps = attempt.RemainingSteps[1:]
					attempt.CurrentStep = attempt.RemainingSteps[0]
				}

				if err := database.Connection.Transaction(func(tx *gorm.DB) error {
					if err := tx.Save(email).Error; err != nil {
						return err
					}

					if attempt.Completed {
						d := handler.GetDeployment(c)
						if err := h.service.ValidateIPCountryRestrictions(c, d.Restrictions); err != nil {
							return err
						}

						if err := tx.Create(signin).Error; err != nil {
							return err
						}
					}

					if err := tx.Model(&model.Session{}).Where("id = ?", session.ID).Updates(map[string]interface{}{
						"active_signin_id": session.ActiveSigninID,
					}).Error; err != nil {
						return err
					}

					handler.RemoveSessionFromCache(session.ID)

					return tx.Save(attempt).Error
				}); err != nil {
					return handler.SendInternalServerError(
						c,
						err,
						"Something went wrong",
					)
				}

				h.service.DeleteOTPFromRedis(
					fmt.Sprintf("signin:%d", attempt.ID),
				)
			}
		case model.SignInAttemptStepVerifyPhone,
			model.SignInAttemptStepVerifyPhoneOTP:
			{
				if attempt.IdentifierID != nil {
					return handler.SendBadRequest(
						c,
						nil,
						"Invalid or expired OTP",
					)
				}

				phone, err := h.service.FindUserByPhoneNumberID(
					*attempt.IdentifierID,
				)
				if err != nil {
					return handler.SendInternalServerError(
						c,
						err,
						"Error fetching user",
					)
				}
				if attempt.CurrentStep == model.SignInAttemptStepVerifyPhoneOTP &&
					phone.Verified {
					return handler.SendBadRequest(
						c,
						nil,
						"Phone number already verified",
					)
				}

				storedOTP, err := h.service.GetOTPFromRedis(
					fmt.Sprintf("signin:%d", attempt.ID),
				)
				if err != nil {
					return handler.SendBadRequest(
						c,
						nil,
						"Invalid or expired OTP",
					)
				}

				if storedOTP != b.VerificationCode {
					return handler.SendBadRequest(
						c,
						nil,
						"Invalid OTP",
					)
				}

				if len(attempt.RemainingSteps) == 1 {
					attempt.Completed = true
					attempt.RemainingSteps = nil
					signin = model.NewSignIn(session.ID, phone.User.ID)
					signin.User = &phone.User

					session.Signins = append(session.Signins, *signin)
					session.ActiveSigninID = &signin.ID
				} else {
					attempt.RemainingSteps = attempt.RemainingSteps[1:]
					attempt.CurrentStep = attempt.RemainingSteps[0]
				}

				if err := database.Connection.Transaction(func(tx *gorm.DB) error {
					phone.Verified = true
					phone.VerifiedAt = time.Now()
					if err := tx.Save(phone).Error; err != nil {
						return err
					}

					if attempt.Completed {
						d := handler.GetDeployment(c)
						if err := h.service.ValidateIPCountryRestrictions(c, d.Restrictions); err != nil {
							return err
						}

						if err := tx.Create(signin).Error; err != nil {
							return err
						}
					}

					if err := tx.Model(&model.Session{}).Where("id = ?", session.ID).Updates(map[string]interface{}{
						"active_signin_id": session.ActiveSigninID,
					}).Error; err != nil {
						return err
					}

					handler.RemoveSessionFromCache(session.ID)

					return tx.Save(attempt).Error
				}); err != nil {
					return handler.SendInternalServerError(
						c,
						err,
						"Something went wrong",
					)
				}

				h.service.DeleteOTPFromRedis(
					fmt.Sprintf("signin:%d", attempt.ID),
				)
			}
		}
	} else {
		attempt, err := h.service.GetSignupAttempt(uint64(attemptIdentifier))
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error fetching sign up attempt")
		}

		storedOTP, err := h.service.GetOTPFromRedis(fmt.Sprintf("signup:%d", attempt.ID))
		if err != nil {
			return handler.SendBadRequest(c, nil, "Invalid or expired OTP")
		}

		if storedOTP != b.VerificationCode {
			return handler.SendBadRequest(c, nil, "Invalid OTP")
		}

		d := handler.GetDeployment(c)

		attempt.RemainingSteps = attempt.RemainingSteps[1:]
		if len(attempt.RemainingSteps) > 0 {
			attempt.CurrentStep = attempt.RemainingSteps[0]

			if err := database.Connection.Save(attempt).Error; err != nil {
				return handler.SendInternalServerError(c, err, "Error saving attempt")
			}
		} else {
			attempt.CurrentStep = ""
			user, err := h.service.CreateVerifiedUser(attempt, d)
			if err != nil {
				return handler.SendInternalServerError(c, err, "Error creating user")
			}

			if err := h.service.ValidateIPCountryRestrictions(c, d.Restrictions); err != nil {
				return handler.SendBadRequest(c, nil, err.Error(), handler.ErrCountryRestricted)
			}

			signIn := model.NewSignIn(session.ID, user.ID)
			signIn.User = user

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

				if err := tx.Model(&model.UserEmailAddress{}).
					Where("id = ?", email.ID).
					Update("user_id", user.ID).
					Error; err != nil {
					return err
				}

				if err := tx.Create(signIn).Error; err != nil {
					return err
				}

				return tx.Model(&session).Update("active_signin_id", signIn.ID).Error
			}); err != nil {
				return handler.SendInternalServerError(c, err, "Something went wrong")
			}
		}

		h.service.DeleteOTPFromRedis(fmt.Sprintf("signup:%d", attempt.ID))
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
	signinErr := database.Connection.Where("id = ? AND session_id = ? AND requires_completion = true", attemptID, session.ID).First(&signinAttempt).Error

	if signinErr == nil {
		// Handle signin profile completion
		return h.handleSigninProfileCompletion(c, &signinAttempt, b, session, deployment)
	}

	// Try to find an OAuth signup attempt
	var signupAttempt model.SignupAttempt
	signupErr := database.Connection.Where("id = ? AND session_id = ? AND is_oauth_signup = true", attemptID, session.ID).First(&signupAttempt).Error

	if signupErr == nil {
		// Handle OAuth signup completion
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
	}

	err := h.service.ValidateSignUpRequest(b, deployment)
	if err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	data := ProfileCompletionData{
		FirstName:   attempt.FirstName,
		LastName:    attempt.LastName,
		Username:    attempt.Username,
		Email:       attempt.Email,
		PhoneNumber: attempt.PhoneNumber,
	}

	missingFields := h.service.CheckMissingFieldsFromData(data, deployment.AuthSettings)

	if len(missingFields) > 0 {
		attempt.MissingFields = datatypes.NewJSONSlice(missingFields)
		database.Connection.Save(&attempt)
		return handler.SendBadRequest(c, nil, "Missing required fields")
	}

	attempt.MissingFields = datatypes.NewJSONSlice([]string{})

	if attempt.PhoneNumber != "" && deployment.AuthSettings.VerificationPolicy.PhoneNumber {
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

		signIn := model.NewSignIn(session.ID, user.ID)
		signIn.User = user

		err = database.Connection.Transaction(func(tx *gorm.DB) error {
			if err := tx.Create(user).Error; err != nil {
				return err
			}

			if err := tx.Create(signIn).Error; err != nil {
				return err
			}

			return tx.Model(&session).Update("active_signin_id", signIn.ID).Error
		})
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error completing signup")
		}

		handler.RemoveSessionFromCache(session.ID)
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
		if err := h.service.ValidatePhoneRestrictions(b.PhoneNumber, deployment.Restrictions); err != nil {
			return handler.SendBadRequest(c, nil, err.Error())
		}

		phoneID := snowflake.ID()
		phone := model.UserPhoneNumber{
			Model:        model.Model{ID: phoneID},
			PhoneNumber:  b.PhoneNumber,
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

	if b.PhoneNumber != "" && deployment.AuthSettings.VerificationPolicy.PhoneNumber {
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

		signIn := model.NewSignIn(session.ID, user.ID)
		signIn.User = &user

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

			return tx.Model(&session).Update("active_signin_id", signIn.ID).Error
		})
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error completing signin")
		}

		handler.RemoveSessionFromCache(session.ID)
		return handler.SendSuccess(c, session)
	}

	if err := database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(&user).Error; err != nil {
			return err
		}
		return tx.Save(&attempt).Error
	}); err != nil {
		return handler.SendInternalServerError(c, err, "Error saving attempt")
	}

	return handler.SendSuccess(c, fiber.Map{
		"signin_attempt": attempt,
		"session":        session,
	})
}

func (h *Handler) ForgotPassword(c *fiber.Ctx) error {
	b, validation := handler.Validate[ForgotPasswordRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	d := handler.GetDeployment(c)

	email, err := h.service.FindUserByEmail(b.Email)
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

	code, err := utils.GenerateOTP()
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Error generating OTP",
			handler.ErrInternal,
		)
	}

	if err := h.service.StoreOTPInCache(fmt.Sprintf("password-reset:%d", email.UserID), code); err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Error storing OTP",
			handler.ErrInternal,
		)
	}

	if err := h.service.SendEmailOTPVerificationAsync(email.EmailAddress, d); err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Error sending email OTP verification",
		)
	}

	return handler.SendSuccess[any](c, nil)
}

func (h *Handler) ResetPassword(c *fiber.Ctx) error {
	b, validation := handler.Validate[ResetPasswordRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	if err := h.service.ValidatePassword(b.Password); err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	email, err := h.service.FindUserByEmail(b.Email)
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

	storedOTP, err := h.service.GetOTPFromRedis(fmt.Sprintf("password-reset:%d", email.UserID))
	if err != nil {
		return handler.SendBadRequest(
			c,
			nil,
			"Invalid or expired OTP",
		)
	}

	if storedOTP != b.OTP {
		return handler.SendBadRequest(
			c,
			nil,
			"Invalid OTP",
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

	if err := database.Connection.Model(&email.User).Update("password", hashedPassword).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Error updating password",
		)
	}

	h.service.DeleteOTPFromRedis(fmt.Sprintf("password-reset:%d", email.UserID))

	return handler.SendSuccess[any](c, nil)
}

func (h *Handler) handleOAuthSignupCompletion(c *fiber.Ctx, attempt *model.SignupAttempt, b *SignUpRequest, session *model.Session, deployment model.Deployment) error {
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
	}

	err := h.service.ValidateSignUpRequest(b, deployment)
	if err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	data := ProfileCompletionData{
		FirstName:   attempt.FirstName,
		LastName:    attempt.LastName,
		Username:    attempt.Username,
		Email:       attempt.Email,
		PhoneNumber: attempt.PhoneNumber,
	}

	missingFields := h.service.CheckMissingFieldsFromData(data, deployment.AuthSettings)

	if len(missingFields) > 0 {
		attempt.MissingFields = datatypes.NewJSONSlice(missingFields)
		database.Connection.Save(attempt)
		return handler.SendBadRequest(c, nil, "Missing required fields")
	}

	attempt.MissingFields = datatypes.NewJSONSlice([]string{})

	// Determine verification steps needed for the completed profile data
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

	// Update remaining steps and current step
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

		signIn := model.NewSignIn(session.ID, user.ID)
		signIn.User = user

		err = database.Connection.Transaction(func(tx *gorm.DB) error {
			if err := tx.Create(user).Error; err != nil {
				return err
			}

			if err := tx.Create(signIn).Error; err != nil {
				return err
			}

			return tx.Model(session).Update("active_signin_id", signIn.ID).Error
		})
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error completing signup")
		}

		handler.RemoveSessionFromCache(session.ID)
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

func (h *Handler) handleSigninProfileCompletion(c *fiber.Ctx, attempt *model.SignInAttempt, b *SignUpRequest, session *model.Session, deployment model.Deployment) error {
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
		if err := h.service.ValidatePhoneRestrictions(b.PhoneNumber, deployment.Restrictions); err != nil {
			return handler.SendBadRequest(c, nil, err.Error())
		}

		phoneID := snowflake.ID()
		phone := model.UserPhoneNumber{
			Model:        model.Model{ID: phoneID},
			PhoneNumber:  b.PhoneNumber,
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
		database.Connection.Save(attempt)
		return handler.SendBadRequest(c, nil, "Missing required fields")
	}

	attempt.RequiresCompletion = false
	attempt.MissingFields = datatypes.NewJSONSlice([]string{})

	// Determine verification steps needed for the completed profile data
	data := ProfileCompletionData{
		FirstName:   b.FirstName,
		LastName:    b.LastName,
		Username:    b.Username,
		Email:       b.Email,
		PhoneNumber: b.PhoneNumber,
	}

	verificationSteps := h.service.DetermineVerificationStepsForProfileCompletion(data, &user.ID, deployment.AuthSettings)

	// Convert string steps to SignInAttemptStep and add to existing steps
	steps := []model.SignInAttemptStep(attempt.RemainingSteps)
	for _, step := range verificationSteps {
		switch step {
		case "verify_email":
			steps = append(steps, model.SignInAttemptStepVerifyEmail)
		case "verify_phone":
			steps = append(steps, model.SignInAttemptStepVerifyPhone)
		}
	}

	// Update remaining steps and current step
	if len(steps) > len(attempt.RemainingSteps) {
		attempt.RemainingSteps = datatypes.NewJSONSlice(steps)
		if attempt.CurrentStep == "" && len(steps) > 0 {
			attempt.CurrentStep = steps[0]
		}
	}

	if len(attempt.RemainingSteps) == 0 {
		if err := h.service.ValidateIPCountryRestrictions(c, deployment.Restrictions); err != nil {
			return handler.SendBadRequest(c, nil, err.Error(), handler.ErrCountryRestricted)
		}

		signIn := model.NewSignIn(session.ID, user.ID)
		signIn.User = &user

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

			return tx.Model(session).Update("active_signin_id", signIn.ID).Error
		})
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error completing signin")
		}

		handler.RemoveSessionFromCache(session.ID)
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
