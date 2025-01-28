package auth

import (
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

		session.SignInAttempts = append(session.SignInAttempts, attempt)

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
		return handler.SendBadRequest(c, nil, err.Error())
	}

	if b.Email != "" && h.service.CheckEmailExists(b.Email) {
		return handler.SendBadRequest(c, nil, "Email is already regsitered", handler.ErrEmailExists)
	}

	hashedPassword, err := h.service.HashPassword(b.Password)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Error hashing password")
	}

	otpSecret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Intellinesia",
		AccountName: b.Email,
	})
	if err != nil {
		return handler.SendInternalServerError(c, err, "Error generating OTP secret")
	}

	completed := !d.AuthSettings.VerificationPolicy.Email

	u := h.service.CreateUser(
		b,
		hashedPassword,
		d.ID,
		d.AuthSettings.SecondFactorPolicy,
		otpSecret.Secret(),
	)

	steps, completed := h.service.DetermineAuthenticationStep(
		completed,
		true,
		false,
		d.AuthSettings,
	)

	attempt := h.service.CreateSignInAttempt(
		u.ID,
		*u.PrimaryEmailAddressID,
		session.ID,
		model.SignInMethodPlainEmail,
		steps,
		completed,
	)

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&u).Error; err != nil {
			return err
		}

		if err := tx.Create(attempt).Error; err != nil {
			return err
		}

		session.SignInAttempts = append(session.SignInAttempts, attempt)
		return nil
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
		session.SignInAttempts = append(session.SignInAttempts, attempt)
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
	signInAttempt := c.QueryInt("sign_in_attempt")
	strategy := c.Query("strategy")

	if signInAttempt == 0 {
		return handler.SendBadRequest(
			c,
			nil,
			"sign_in_attempt is required",
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

	attempt, err := h.service.GetSignInAttempt(uint(signInAttempt))
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
	case model.SignInAttemptStepVerifyEmail, model.SignInAttemptStepVerifyEmailOTP:
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

		h.service.SendEmailOTPVerification(email.Email, code)
	case model.SignInAttemptStepVerifySecondFactor:
		return handler.SendSuccess[any](c, nil)
	case model.SignInAttemptStepVerifyPhone:
		return handler.SendSuccess[any](c, nil)
	case model.SignInAttemptStepVerifyPhoneOTP:
		return handler.SendSuccess[any](c, nil)
	default:
		return handler.SendBadRequest(c, nil, "Invalid step")
	}

	return handler.SendSuccess[any](c, nil)
}

// func generateBackupCodes(userID uint, db *gorm.DB) ([]string, error) {
// 	const backupCodeCount = 2

// 	var user model.User
// 	if err := db.Where("id = ?", userID).First(&user).Error; err != nil {
// 		return nil, fmt.Errorf("failed to find user with ID %d: %w", userID, err)
// 	}

// 	if len(user.BackupCodes) > 0 {
// 		return nil, fmt.Errorf("backup codes already exist for user ID %d", userID)
// 	}

// 	var rawCodes []string
// 	var hashedCodes []string
// 	for i := 0; i < backupCodeCount; i++ {
// 		rawCode := fmt.Sprintf("%d", snowflake.ID())
// 		rawCodes = append(rawCodes, rawCode)

// 		hashedCode, err := bcrypt.GenerateFromPassword([]byte(rawCode), bcrypt.DefaultCost)
// 		if err != nil {
// 			return nil, fmt.Errorf("failed to hash backup code: %w", err)
// 		}
// 		hashedCodes = append(hashedCodes, string(hashedCode))
// 	}

// 	user.BackupCodes = hashedCodes
// 	if err := db.Save(&user).Error; err != nil {
// 		return nil, fmt.Errorf("failed to save backup codes for user ID %d: %w", userID, err)
// 	}

// 	return rawCodes, nil
// }

func (h *Handler) CompleteVerification(c *fiber.Ctx) error {
	signinattempt := c.QueryInt("sign_in_attempt")
	session := handler.GetSession(c)
	if signinattempt == 0 {
		return handler.SendBadRequest(c, nil, "sign_in_attempt is required")
	}

	attempt, err := h.service.GetSignInAttempt(uint(signinattempt))
	if err != nil {
		return handler.SendInternalServerError(c, err, "Error fetching sign in attempt")
	}
	if attempt.Completed {
		return handler.SendBadRequest(c, nil, "Sign in attempt already completed")
	}

	b, verr := handler.Validate[VerifyOTPRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
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

			valid := totp.Validate(b.VerificationCode, email.User.OtpSecret)
			if !valid {
				return handler.SendBadRequest(c, nil, "Invalid OTP")
			}

			if len(attempt.Steps) == 1 {
				attempt.Completed = true
				attempt.Steps = nil
				signin = model.NewSignIn(session.ID, email.UserID)
				signin.User = &email.User

				session.SignIns = append(session.SignIns, signin)
				session.ActiveSignIn = signin
			} else {
				attempt.Steps = attempt.Steps[1:]
				attempt.CurrentStep = attempt.Steps[0]
			}

			if !email.Verified {
				email.Verified = true
				email.VerificationStrategy = model.Otp
				email.VerifiedAt = time.Now()
			}

			if err := h.service.db.Transaction(func(tx *gorm.DB) error {
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

			return handler.SendSuccess[any](c, session)
		}
	}

	return handler.SendSuccess[any](c, nil)
}
