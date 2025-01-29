package auth

import (
	"fmt"
	"time"

	"github.com/godruoyi/go-snowflake"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/utils"
	"github.com/pquerna/otp/totp"
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
	b, verr := handler.Validate[SignInRequest](c)

	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	d := handler.GetDeployment(c)
	session := handler.GetSession(c)

	email, err := h.service.FindUserByEmail(b.Email)
	if err != nil {
		if err == handler.ErrUserNotFound {
			return handler.SendNotFound(c, nil, err.Error(), handler.ErrUserNotFound)
		}
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	if err := h.service.ValidateUserStatus(email); err != nil {
		return handler.SendForbidden(c, nil, err.Error(), handler.ErrUserDisabled)
	}

	authenticated := false

	if b.Password != "" {
		match, err := h.service.VerifyPassword(email.User.Password, b.Password)
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error comparing password")
		}

		if !match {
			return handler.SendUnauthorized(
				c,
				nil,
				"Invalid credentials",
				handler.ErrInvalidCredentials,
			)
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
		email.ID,
		session.ID,
		model.SignInMethodPlainEmail,
		steps,
		completed,
	)

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(attempt).Error; err != nil {
			return err
		}

		if completed {
			signIn := model.NewSignIn(session.ID, email.User.ID)
			if err := tx.Create(signIn).Error; err != nil {
				return err
			}
			signIn.User = &email.User

			session.SignIns = append(session.SignIns, signIn)
			session.ActiveSignInID = signIn.ID
		}

		session.SigninAttempts = append(session.SigninAttempts, attempt)

		return tx.Save(session).Error
	})
	if err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	return handler.SendSuccess(c, session)
}

func (h *Handler) SignUp(c *fiber.Ctx) error {
	b, verr := handler.Validate[SignUpRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	if err := h.service.ValidatePassword(b.Password); err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	d := handler.GetDeployment(c)
	session := handler.GetSession(c)

	if err := h.service.ValidateSignUpRequest(b, d); err != nil {
		return handler.SendBadRequest(c, nil, err.Error(), handler.ErrBadRequestBody)
	}

	if b.Email != "" && h.service.CheckEmailExists(b.Email) {
		return handler.SendBadRequest(c, nil, "Email is already registered", handler.ErrEmailExists)
	}

	hashedPassword, err := h.service.HashPassword(b.Password)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Error hashing password")
	}

	attempt, err := h.service.CreateSignupAttempt(b, hashedPassword, session, d)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Error creating signup attempt")
	}

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(attempt).Error; err != nil {
			return err
		}

		session.SignupAttempts = append(session.SignupAttempts, attempt)

		if len(attempt.RemainingSteps) == 0 {
			otpSecret, err := totp.Generate(totp.GenerateOpts{
				Issuer:      d.Project.Name,
				AccountName: attempt.Email,
			})
			if err != nil {
				return err
			}

			u := h.service.CreateUser(
				b,
				attempt.Password,
				d.ID,
				d.AuthSettings.SecondFactorPolicy,
				otpSecret.Secret(),
				!d.AuthSettings.VerificationPolicy.Email,
			)

			if err := tx.Create(&u).Error; err != nil {
				return err
			}

			signIn := model.NewSignIn(session.ID, u.ID)
			signIn.User = &u

			if err := tx.Create(signIn).Error; err != nil {
				return err
			}

			session.SignIns = append(session.SignIns, signIn)
			session.ActiveSignInID = signIn.ID
		}

		return tx.Save(session).Error
	})

	if err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
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
			"sso provider is required",
			handler.ErrProviderRequired,
		)
	}

	session := handler.GetSession(c)
	attempt := model.NewSignInAttempt(model.SignInMethodSSO)
	attempt.Method = model.SignInMethodSSO
	attempt.SessionID = session.ID
	attempt.SSOProvider = provider

	err := database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(attempt).Error; err != nil {
			return err
		}
		session.SigninAttempts = append(session.SigninAttempts, attempt)
		return nil
	})
	if err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	url := utils.GenerateVerificationUrl(provider, *attempt)
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
		return handler.SendBadRequest(c, nil, "code is not present in uri", handler.ErrCodeRequired)
	}

	var attempt model.SignInAttempt
	if err := database.Connection.Where("id = ?", c.Query("state")).First(&attempt).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to find sign in attempt",
			handler.ErrInvalidState,
		)
	}

	conf := getOAuthConfig(attempt.SSOProvider)
	token, err := conf.Exchange(c.Context(), code)
	if err != nil || !token.Valid() {
		return handler.SendBadRequest(
			c,
			nil,
			"Failed to exchange code for token",
			handler.ErrInvalidCode,
		)
	}

	user, err := utils.ExchangeTokenForUser(token, attempt.SSOProvider)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to get user info")
	}

	var email model.UserEmailAddress
	exists := database.Connection.Joins(
		"User",
		database.Connection.Where(&model.User{DeploymentID: deployment.ID}),
	).Preload("User.SocialConnections").
		Where("email = ?", user.Email).First(&email).RowsAffected > 0

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		if exists {
			return h.service.HandleExistingUser(
				tx,
				&email,
				token,
				&attempt,
				deployment.AuthSettings,
			)
		}

		otpSecret, err := totp.Generate(totp.GenerateOpts{
			Issuer:      deployment.Project.Name,
			AccountName: user.Email,
		})
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error generating OTP secret")
		}

		primaryAddressID := uint(snowflake.ID())

		u := model.User{
			Model:                 model.Model{ID: uint(snowflake.ID())},
			SchemaVersion:         model.SchemaVersionV1,
			SecondFactorPolicy:    deployment.AuthSettings.SecondFactorPolicy,
			DeploymentID:          deployment.ID,
			OtpSecret:             otpSecret.Secret(),
			PrimaryEmailAddressID: &primaryAddressID,
		}

		if err := tx.Create(&u).Error; err != nil {
			return err
		}

		email := model.UserEmailAddress{
			Model:     model.Model{ID: primaryAddressID},
			Email:     user.Email,
			IsPrimary: true,
			UserID:    u.ID,
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
		signIn := model.NewSignIn(session.ID, u.ID)

		if err := tx.Create(&connection).Error; err != nil {
			return err
		}

		if err := tx.Create(&signIn).Error; err != nil {
			return err
		}

		session.SignIns = append(session.SignIns, signIn)
		return nil
	})
	if err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	return handler.SendSuccess(c, session)
}

func (h *Handler) CheckIdentifierAvailability(c *fiber.Ctx) error {
	identifier := c.Query("identifier")
	identifierType := c.Query("type")
	exists, err := h.service.CheckIdentifierAvailability(identifier, identifierType)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}
	return handler.SendSuccess(c, fiber.Map{
		"exists": exists,
	})
}

func (h *Handler) PrepareVerification(c *fiber.Ctx) error {
	attemptIdentifier := c.QueryInt("attempt_identifier")
	identifierType := c.Query("identifier_type")
	strategy := c.Query("strategy")

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
		attempt, err := h.service.GetSignInAttempt(uint(attemptIdentifier))
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
			email, err := h.service.FindUserByEmailID(attempt.IdentifierID)
			if err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error fetching user",
					handler.ErrInvalidSignInAttempt,
				)
			}

			if attempt.CurrentStep == model.SignInAttemptStepVerifyEmailOTP && email.Verified {
				return handler.SendBadRequest(
					c,
					nil,
					"Email already verified",
					handler.ErrInvalidSignInAttempt,
				)
			}

			code, err := totp.GenerateCode(email.User.OtpSecret, time.Now())
			if err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error generating OTP",
					handler.ErrInternal,
				)
			}

			if err := h.service.StoreOTPInRedis(fmt.Sprintf("signin:%d", attempt.ID), code); err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Error storing OTP",
					handler.ErrInternal,
				)
			}

			h.service.SendEmailOTPVerification(email.Email, code)
		case model.SignInAttemptStepVerifyPhoneOTP:
			return handler.SendSuccess[any](c, nil)
		default:
			return handler.SendBadRequest(c, nil, "Invalid step")
		}
	} else {
		attempt, err := h.service.GetSignupAttempt(uint(attemptIdentifier))
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
			key, err := totp.Generate(totp.GenerateOpts{})
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

			if err := h.service.StoreOTPInRedis(fmt.Sprintf("signup:%d", attempt.ID), code); err != nil {
				return handler.SendInternalServerError(
					c,
					err,
					"Something went wrong",
					handler.ErrInternal,
				)
			}

			h.service.SendEmailOTPVerification(attempt.Email, code)
		case model.SignupAttemptStepVerifyPhone:
			return handler.SendSuccess[any](c, nil)
		default:
			return handler.SendBadRequest(c, nil, "Invalid step")
		}
	}

	return handler.SendSuccess[any](c, nil)
}

func (h *Handler) CompleteVerification(c *fiber.Ctx) error {
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

	b, verr := handler.Validate[VerifyOTPRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	if identifierType == "signin" {
		attempt, err := h.service.GetSignInAttempt(uint(attemptIdentifier))
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error fetching sign in attempt")
		}
		if attempt.Completed {
			return handler.SendBadRequest(c, nil, "Sign in attempt already completed")
		}

		var signin *model.SignIn

		switch attempt.CurrentStep {
		case model.SignInAttemptStepVerifyEmail, model.SignInAttemptStepVerifyEmailOTP:
			{
				email, err := h.service.FindUserByEmailID(attempt.IdentifierID)
				if err != nil {
					return handler.SendInternalServerError(c, err, "Error fetching user")
				}
				if attempt.CurrentStep == model.SignInAttemptStepVerifyEmailOTP && email.Verified {
					return handler.SendBadRequest(c, nil, "Email already verified")
				}

				storedOTP, err := h.service.GetOTPFromRedis(fmt.Sprintf("signin:%d", attempt.ID))
				if err != nil {
					return handler.SendBadRequest(c, nil, "Invalid or expired OTP")
				}

				if storedOTP != b.VerificationCode {
					return handler.SendBadRequest(c, nil, "Invalid OTP")
				}

				if len(attempt.RemainingSteps) == 1 {
					attempt.Completed = true
					attempt.RemainingSteps = nil
					signin = model.NewSignIn(session.ID, email.UserID)
					signin.User = &email.User

					session.SignIns = append(session.SignIns, signin)
					session.ActiveSignInID = signin.ID
				} else {
					attempt.RemainingSteps = attempt.RemainingSteps[1:]
					attempt.CurrentStep = attempt.RemainingSteps[0]
				}

				if err := database.Connection.Transaction(func(tx *gorm.DB) error {
					if err := tx.Save(email).Error; err != nil {
						return err
					}

					if attempt.Completed {
						if err := tx.Create(signin).Error; err != nil {
							return err
						}
					}

					handler.RemoveSessionFromCache(session.ID)

					return tx.Save(attempt).Error
				}); err != nil {
					return handler.SendInternalServerError(c, err, "Something went wrong")
				}

				h.service.DeleteOTPFromRedis(fmt.Sprintf("signin:%d", attempt.ID))
			}
		}
	} else {
		attempt, err := h.service.GetSignupAttempt(uint(attemptIdentifier))
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
		otpSecret, err := totp.Generate(totp.GenerateOpts{
			Issuer:      d.Project.Name,
			AccountName: attempt.Email,
		})
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error generating OTP secret")
		}

		user, err := h.service.CreateVerifiedUser(attempt, d, otpSecret.Secret())
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error creating user")
		}

		signIn := model.NewSignIn(session.ID, user.ID)
		signIn.User = user

		if err := database.Connection.Transaction(func(tx *gorm.DB) error {
			if err := tx.Create(user).Error; err != nil {
				return err
			}

			if err := tx.Create(signIn).Error; err != nil {
				return err
			}

			session.SignIns = append(session.SignIns, signIn)
			session.ActiveSignInID = signIn.ID

			attempt.RemainingSteps = attempt.RemainingSteps[1:]
			if len(attempt.RemainingSteps) > 0 {
				attempt.CurrentStep = attempt.RemainingSteps[0]
			} else {
				attempt.CurrentStep = ""
			}

			return tx.Save(session).Error
		}); err != nil {
			return handler.SendInternalServerError(c, err, "Something went wrong")
		}

		h.service.DeleteOTPFromRedis(fmt.Sprintf("signup:%d", attempt.ID))
	}

	return handler.SendSuccess(c, session)
}
