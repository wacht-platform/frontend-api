package auth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"image/png"
	"log"
	"net/smtp"
	"regexp"
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

//function for validate password
func validatePassword(password string) error {
	var ErrInvalidPassword = errors.New("password must be 6-125 characters long, contain at least one number, and one symbol")

	if len(password) < 6 || len(password) > 125 {
		return ErrInvalidPassword
	}

	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	if !hasNumber {
		return ErrInvalidPassword
	}

	hasSymbol := regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password)
	if !hasSymbol {
		return ErrInvalidPassword
	}
	return nil
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

	secondFactorEnforced := d.AuthSettings.SecondFactorPolicy == model.SecondFactorPolicyEnforced ||
		email.User.SecondFactorPolicy == model.SecondFactorPolicyEnforced

		if (d.AuthSettings.SecondFactor == model.SecondFactorEmailOTP || d.AuthSettings.SecondFactor == model.SecondFactorAuthenticator) && !email.Verified {
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

	step, completed := h.service.DetermineAuthenticationStep(email.Verified, authenticated, secondFactorEnforced, d.AuthSettings)
	attempt := h.service.CreateSignInAttempt(b.Email, session.ID, authenticated, secondFactorEnforced, step, completed, email.User.LastActiveOrgID)

	if authenticated && secondFactorEnforced && d.AuthSettings.SecondFactor == model.SecondFactorEmailOTP {
		passcode, err := totp.GenerateCode(email.User.OtpSecret, time.Now())
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error generating OTP")
		}

		primaryEmailAddress := email.Email
		if err := SendOTP(primaryEmailAddress, passcode); err != nil {
			log.Println("Error sending OTP email: ", err)
			return handler.SendInternalServerError(c, err, "Error sending OTP email")
		}

		log.Printf("Generated Passcode for %s: %s\n", primaryEmailAddress, passcode)
	}

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

	if err := validatePassword(b.Password); err != nil {
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

	u := h.service.CreateUser(b, hashedPassword, d.ID, d.AuthSettings.SecondFactorPolicy, otpSecret.Secret())
	attempt := h.service.CreateSignInAttempt(b.Email, session.ID, false, false, model.SessionStepVerifyEmailOTP, completed, 0)

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

	if completed {
		passcode, err := totp.GenerateCode(u.OtpSecret, time.Now())
		if err != nil {
			return handler.SendInternalServerError(c, err, "Error generating passcode")
		}

		var primaryEmailAddress string
		if len(u.UserEmailAddresses) > 0 {
			for _, email := range u.UserEmailAddresses {
				if email.ID == u.PrimaryEmailAddressID {
					primaryEmailAddress = email.Email
					break
				}
			}
		} else {
			primaryEmailAddress = ""
		}

		fmt.Printf("Generated Passcode for %s: %s\n", primaryEmailAddress, passcode)

		if err := SendOTP(primaryEmailAddress, passcode); err != nil {
			log.Println("Error sending OTP email: ", err)
			return handler.SendInternalServerError(c, err, "Error sending OTP email")
		}
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
	exists := database.Connection.Joins("User", database.Connection.Where(&model.User{DeploymentID: deployment.ID})).
		Preload("User.SocialConnections").Where("email = ?", user.Email).
		First(&email).RowsAffected > 0

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
	return handler.SendSuccess[any](c, nil)
}

//Send OTP handler
func SendOTP(email string, otp string) error {
  smtpHost :=  "smtp.zeptomail.in"
	smtpPort := "587"
	username := "emailapikey"
	password := "PHtE6r1cR7rsgmEsoEMI4vPsRMWlZ41/r75kK1EWstkUA6NRGE0H+dt9kmPkoxopA6NGEvKZyNlgsrLK5rmDIT7qMjtEWWqyqK3sx/VYSPOZsbq6x00VtFoedELVU4TodNJj0Czfs97bNA=="
	from := "marketing@wacht.tech"

  auth := smtp.PlainAuth("", username, password, smtpHost)

  htmlBody := fmt.Sprintf(`
  <div style="font-family: Helvetica, Arial, sans-serif; max-width: 90%%; margin: auto; line-height: 1.6; color: #333; padding: 20px; box-sizing: border-box;">
    <div style="margin: auto; padding: 20px; background: #f9f9f9; border-radius: 8px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);">
      <div style="border-bottom: 2px solid #000; padding-bottom: 10px; margin-bottom: 20px;">
        <a href="#" style="font-size: 1.5em; color: #000; text-decoration: none; font-weight: bold;">Intellinesia</a>
      </div>
      <p style="font-size: 1.2em; margin-bottom: 10px;">Hi,</p>
      <p style="margin-bottom: 20px;">Thank you for choosing Wacht. Use the following OTP to complete your Sign Up procedures. OTP is valid for 5 minutes:</p>
      <h2 style="background: #000; color: #fff; padding: 10px 20px; border-radius: 5px; display: inline-block; margin: 0 auto;">%s</h2>
      <p style="font-size: 1em; margin-top: 20px;">Regards,<br><strong>Wacht</strong></p>
      <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
      <div style="text-align: right; color: #aaa; font-size: 0.9em; line-height: 1.4;">
        <p style="margin: 0;">Intellinesia LTD</p>
        <p style="margin: 0;">Kolkata</p>
        <p style="margin: 0;">India</p>
      </div>
    </div>
  </div>
  `, otp)

	subject := "Subject: Your OTP Code\r\n"
	contentType := "MIME-Version: 1.0\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n"
	msg := []byte(subject + contentType + htmlBody)


  smtpServer := fmt.Sprintf("%s:%s", smtpHost, smtpPort)
	err := smtp.SendMail(smtpServer, auth, from, []string{email}, msg)
	if err != nil {
		return fmt.Errorf("failed to send email to %s: %w", email, err)
	}

  return nil
}

//Generate Backup
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

//Verify OTP handler
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

//Initiate Password Reset handler
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

	if err := SendOTP(primaryEmailAddress, passcode); err != nil {
		log.Println("Error sending OTP email: ", err)
		return handler.SendInternalServerError(c, err, "Error sending OTP email")
	}

	session := handler.GetSession(c)
	attempt := h.service.CreateSignInAttempt(
		b.Email, 
		session.ID, 
		false, 
		false, 
		model.SessionStepPasswordResetInitiation, 
		false, 
		0,
	)

	if err := database.Connection.Create(attempt).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Error logging password reset attempt")
	}

	return handler.SendSuccess(c, fiber.Map{
		"message": "Passcode sent successfully",
	})
}

//Setup Authenticator handler
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

//Reset Password handler
func (h *Handler) ResetPassword(c *fiber.Ctx) error {
	b, verr := handler.Validate[ResetPasswordRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	var email model.UserEmailAddress
	if err := database.Connection.Where("email = ?", b.Email).First(&email).Error; err != nil {
		return handler.SendNotFound(c, nil, "Email not found")
	}

	if err := validatePassword(b.Password); err != nil {
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
		b.Email,
		session.ID,
		true,
		false,
		model.SessionStepPasswordResetCompletion,
		true,
		0,
	)

	if err := database.Connection.Create(attempt).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Error logging password reset attempt")
	}


	return handler.SendSuccess(c, fiber.Map{
		"message": "Password updated successfully",
	})
}