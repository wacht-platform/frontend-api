package auth

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"log"
	"time"

	"github.com/godruoyi/go-snowflake"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/utils"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
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
		if err == ErrUserNotFound {
			return handler.SendNotFound(c, nil, err.Error())
		}
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	if err := h.service.ValidateUserStatus(email); err != nil {
		return handler.SendForbidden(c, nil, err.Error())
	}

	secondFactorEnforced :=
		d.AuthSettings.SecondFactorPolicy == model.SecondFactorPolicyEnforced ||
			email.User.SecondFactorPolicy == model.SecondFactorPolicyEnforced

	if (d.AuthSettings.SecondFactor == model.SecondFactorEmailOTP ||
		d.AuthSettings.SecondFactor == model.SecondFactorAuthenticator ||
		email.User.SecondFactorPolicy == model.SecondFactorPolicyEnforced) &&
		!email.Verified {
		return handler.SendForbidden(c, nil, "Second factor verification required before sign-in.")
	}

	authenticated := false
	if b.Password != "" {
		match, err := h.service.VerifyPassword(email.User.Password, b.Password)
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error comparing password")
		}

		if !match {
			return handler.SendUnauthorized(c, nil, ErrInvalidCredentials.Error())
		}
		authenticated = true
	}

	step, completed := h.service.DetermineAuthenticationStep(
		email.Verified,
		authenticated,
		secondFactorEnforced,
		d.AuthSettings,
	)

	log.Printf("Step: %s, Completed: %t", step, completed)
	completed = true

	attempt := h.service.CreateSignInAttempt(
		email.UserID,
		email.ID,
		session.ID,
		model.SignInMethodPlainEmail,
		authenticated,
		secondFactorEnforced,
		step,
		completed,
		email.User.LastActiveOrgID,
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
		return handler.SendBadRequest(c, nil, ErrEmailExists.Error())
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

	totpSecret := otpSecret.Secret()
	log.Printf("OTP Secret: %s", totpSecret)

	completed := !d.AuthSettings.VerificationPolicy.Email

	u := h.service.CreateUser(
		b,
		hashedPassword,
		d.ID,
		d.AuthSettings.SecondFactorPolicy,
		otpSecret.Secret(),
	)

	attempt := h.service.CreateSignInAttempt(
		u.ID,
		session.ID,
		u.PrimaryEmailAddressID,
		model.SignInMethodPlainEmail,
		false,
		false,
		model.SessionStepVerifyEmailOTP,
		completed,
		0,
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
	provider := model.SSOProvider(c.Query("provider"))
	if provider == "" {
		return handler.SendBadRequest(c, nil, ErrProviderRequired.Error())
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
		return handler.SendBadRequest(c, nil, ErrCodeRequired.Error())
	}

	var attempt model.SignInAttempt
	if err := database.Connection.Where("id = ?", c.Query("state")).First(&attempt).Error; err != nil {
		return handler.SendInternalServerError(c, err, ErrInvalidState.Error())
	}

	conf := getOAuthConfig(attempt.SSOProvider)
	token, err := conf.Exchange(c.Context(), code)
	if err != nil || !token.Valid() {
		return handler.SendBadRequest(c, nil, ErrInvalidCode.Error())
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
			return h.service.HandleExistingUser(tx, &email, token, &attempt, deployment.AuthSettings)
		}

		otpSecret, err := totp.Generate(totp.GenerateOpts{
			Issuer:      deployment.Project.Name,
			AccountName: user.Email,
		})
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error generating OTP secret")
		}

		u := model.User{
			Model:                 model.Model{ID: uint(snowflake.ID())},
			SchemaVersion:         model.SchemaVersionV1,
			SecondFactorPolicy:    deployment.AuthSettings.SecondFactorPolicy,
			DeploymentID:          deployment.ID,
			OtpSecret:             otpSecret.Secret(),
			PrimaryEmailAddressID: uint(snowflake.ID()),
		}

		if err := tx.Create(&u).Error; err != nil {
			return err
		}

		email := model.UserEmailAddress{
			Model:     model.Model{ID: u.PrimaryEmailAddressID},
			Email:     user.Email,
			IsPrimary: true,
			UserID:    u.ID,
		}

		if err := tx.Create(&email).Error; err != nil {
			return err
		}

		connection := h.service.CreateSocialConnection(u.ID, email.ID, attempt.SSOProvider, user.Email, token)
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
		return handler.SendBadRequest(c, nil, "sign_in_attempt is required")
	}

	if strategy == "" {
		return handler.SendBadRequest(c, nil, "strategy is required")
	}

	attempt, err := h.service.GetSignInAttempt(uint(signInAttempt))
	if err != nil {
		return handler.SendInternalServerError(c, err, "Error fetching sign in attempt")
	}

	if attempt.Completed {
		return handler.SendBadRequest(c, nil, "Sign in attempt already completed")
	}

	switch attempt.CurrentStep {
	case model.SessionStepVerifyEmail:
	case model.SessionStepVerifyEmailOTP:
		// user := h.service.FindUserByEmail()
		// h.service.SendEmailOTPVerification(, "")
	case model.SessionStepVerifySecondFactor:
		return handler.SendSuccess[any](c, nil)
	case model.SessionStepVerifyPhone:
		return handler.SendSuccess[any](c, nil)
	case model.SessionStepVerifyPhoneOTP:
		return handler.SendSuccess[any](c, nil)
	}

	return handler.SendSuccess[any](c, nil)
}

func generateBackupCodes(userID uint, db *gorm.DB) ([]string, error) {
	const backupCodeCount = 2

	var user model.User
	if err := db.Where("id = ?", userID).First(&user).Error; err != nil {
		return nil, fmt.Errorf("failed to find user with ID %d: %w", userID, err)
	}

	if len(user.BackupCodes) > 0 {
		return nil, fmt.Errorf("backup codes already exist for user ID %d", userID)
	}

	var rawCodes []string
	var hashedCodes []string
	for i := 0; i < backupCodeCount; i++ {
		rawCode := fmt.Sprintf("%d", snowflake.ID())
		rawCodes = append(rawCodes, rawCode)

		hashedCode, err := bcrypt.GenerateFromPassword([]byte(rawCode), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash backup code: %w", err)
		}
		hashedCodes = append(hashedCodes, string(hashedCode))
	}

	user.BackupCodes = hashedCodes
	if err := db.Save(&user).Error; err != nil {
		return nil, fmt.Errorf("failed to save backup codes for user ID %d: %w", userID, err)
	}

	return rawCodes, nil
}

func (h *Handler) VerifyOTP(c *fiber.Ctx) error {
	b, verr := handler.Validate[VerifyOTPRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	var email model.UserEmailAddress
	if err := database.Connection.Where("email = ?", b.Email).First(&email).Error; err != nil {
		return handler.SendNotFound(c, nil, "Email not found")
	}

	valid := totp.Validate(b.Passcode, email.User.OtpSecret)
	if !valid {
		return handler.SendBadRequest(c, nil, "Invalid passcode")
	}

	email.Verified = true
	email.VerifiedAt = time.Now()

	if err := database.Connection.Save(&email).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Error updating verification status")
	}

	return handler.SendSuccess(c, fiber.Map{
		"message": "Email verified successfully",
	})
}

func (h *Handler) PreparePasswordReset(c *fiber.Ctx) error {
	b, verr := handler.Validate[PrepareVerificationRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	var email model.UserEmailAddress
	if err := database.Connection.Where("email = ?", b.Email).First(&email).Error; err != nil {
		return handler.SendNotFound(c, nil, "Email not found")
	}

	passcode, err := totp.GenerateCode(email.User.OtpSecret, time.Now())
	if err != nil {
		return handler.SendInternalServerError(c, err, "Error generating passcode")
	}

	var primaryEmailAddress string
	if len(email.User.UserEmailAddresses) > 0 {
		for _, userEmail := range email.User.UserEmailAddresses {
			if userEmail.ID == email.User.PrimaryEmailAddressID {
				primaryEmailAddress = userEmail.Email
				break
			}
		}
	} else {
		primaryEmailAddress = ""
	}

	fmt.Printf("Generated Passcode for %s: %s\n", primaryEmailAddress, passcode)

	if err := h.service.SendEmailOTPVerification(primaryEmailAddress, passcode); err != nil {
		log.Println("Error sending OTP email: ", err)
		return handler.SendInternalServerError(c, err, "Error sending OTP email")
	}

	session := handler.GetSession(c)
	attempt := h.service.CreateSignInAttempt(
		email.UserID,
		session.ID,
		email.ID,
		model.SignInMethodPlainEmail,
		false,
		false,
		model.SessionStepPasswordResetInitiation,
		false,
		email.User.LastActiveOrgID,
	)

	if err := database.Connection.Create(attempt).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Error logging password reset attempt")
	}

	return handler.SendSuccess(c, fiber.Map{
		"message": "Passcode sent successfully",
	})
}

func (h *Handler) SetupAuthenticator(c *fiber.Ctx) error {
	b, verr := handler.Validate[SetupAuthenticatorRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	var email model.UserEmailAddress
	if err := database.Connection.Where("email = ?", b.Email).First(&email).Error; err != nil {
		return handler.SendNotFound(c, nil, "Email not found")
	}

	secret := email.User.OtpSecret

	if secret == "" {
		return handler.SendBadRequest(c, nil, "OTP secret not found. Please make sure the authenticator is set up.")
	}

	otpKey, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Intellinesia",
		AccountName: b.Email,
		Secret:      []byte(secret),
	})
	if err != nil {
		return handler.SendInternalServerError(c, err, "Error generating OTP key")
	}

	var buf bytes.Buffer
	img, err := otpKey.Image(200, 200)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Error generating QR code")
	}
	png.Encode(&buf, img)

	backupCodes, err := generateBackupCodes(email.User.ID, database.Connection)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Error generating backup codes")
	}

	return c.JSON(fiber.Map{
		"message":       "Scan the QR code with your authenticator app to complete setup",
		"qr_code_image": base64.StdEncoding.EncodeToString(buf.Bytes()),
		"backup_codes":  backupCodes,
	})
}

// Reset Password handler
func (h *Handler) ResetPassword(c *fiber.Ctx) error {
	b, verr := handler.Validate[ResetPasswordRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	var email model.UserEmailAddress
	if err := database.Connection.Where("email = ?", b.Email).First(&email).Error; err != nil {
		return handler.SendNotFound(c, nil, "Email not found")
	}

	if err := h.service.ValidatePassword(b.Password); err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	hashedPassword, err := h.service.HashPassword(b.Password)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Error hashing password")
	}

	email.User.Password = hashedPassword
	if err := database.Connection.Save(&email.User).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Error updating password")
	}

	session := handler.GetSession(c)
	attempt := h.service.CreateSignInAttempt(
		email.UserID,
		session.ID,
		email.ID,
		model.SignInMethodPlainEmail,
		true,
		false,
		model.SessionStepPasswordResetCompletion,
		true,
		email.User.LastActiveOrgID,
	)

	if err := database.Connection.Create(attempt).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Error logging password reset attempt")
	}

	return handler.SendSuccess(c, fiber.Map{
		"message": "Password updated successfully",
	})
}

// business logic (apart from hanlder )
// sign in app -> Sign IN atytemnpt -> send back to the user
