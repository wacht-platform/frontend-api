package auth

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/godruoyi/go-snowflake"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/config"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/utils"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/pquerna/otp/totp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
	"gorm.io/gorm"

	"net/smtp"
)

func signJWT(sessionID uint, iss string, exp time.Time, keypair model.DeploymentKeyPair) (string, error) {
	tok, err := jwt.NewBuilder().
		Issuer(fmt.Sprintf("https://%s", iss)).
		Expiration(exp).
		IssuedAt(time.Now()).
		NotBefore(time.Now()).
		Claim("sess", sessionID).
		Build()
	if err != nil {
		return "", err
	}

	privateKeyBlock, _ := pem.Decode([]byte(keypair.PrivateKey))
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)

	if err != nil {
		log.Fatal("Error parsing private key: ", err)
	}

	if err != nil {
		return "", err
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), privateKey))

	return string(signed), err
}

func createSession(method model.SignInMethod, email string, completed bool, step model.CurrentSessionStep, tx *gorm.DB, userID uint) (*model.Session, *model.SignInAttempt, error) {
	session := model.NewSession()
	attempt := model.NewSignInAttempt(method)
	attempt.Method = method
	attempt.CurrenStep = step
	attempt.Completed = completed
	attempt.Email = email

	if err := tx.Create(&session).Error; err != nil {
		return nil, nil, err
	}

	attempt.SessionID = session.ID

	var signIn model.SignIn

	if completed && userID != 0 {
		signIn = model.SignIn{
			Model:     model.Model{ID: uint(snowflake.ID())},
			SessionID: session.ID,
			UserID:    userID,
		}
		if err := tx.Create(&signIn).Error; err != nil {
			return nil, nil, err
		}
	}

	if err := tx.Create(&attempt).Error; err != nil {
		return nil, nil, err
	}

	session.SignInAttempts = append(session.SignInAttempts, *attempt)
	session.SignIns = append(session.SignIns, signIn)
	session.ActiveSignInID = signIn.ID
	return session, attempt, nil
}

func SignIn(c *fiber.Ctx) error {
	b, verr := handler.Validate[SignInRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	d := handler.GetDeployment(c)

	var email model.UserEmailAddress
	if res := database.Connection.Where(&model.UserEmailAddress{Email: b.Email}).Joins("User").First(&email); res.RowsAffected == 0 {
		return handler.SendNotFound(c, nil, "User not found")
	} else if res.Error != nil {
		return handler.SendInternalServerError(c, res.Error, "Something went wrong")
	}

	if email.User.Disabled {
		return handler.SendForbidden(c, nil, "User is disabled")
	}

	secondFactorEnforced := d.AuthSettings.SecondFactorPolicy == model.SecondFactorPolicyEnforced ||
		email.User.SecondFactorPolicy == model.SecondFactorPolicyEnforced

	authenticated := false
	if b.Password != "" {
		match, err := utils.ComparePassword(email.User.Password, b.Password)
		if err != nil {
			return handler.SendInternalServerError(c, nil, "Error comparing password")
		}
		if !match {
			return handler.SendUnauthorized(c, nil, "Invalid credentials")
		}
		authenticated = true
	}

	var step model.CurrentSessionStep
	completed := false

	if !authenticated {
		if d.AuthSettings.FirstFactor == model.FirstFactorEmailPassword {
			step = model.SessionStepVerifyPassword
		} else if d.AuthSettings.FirstFactor == model.FirstFactorEmailOTP {
			step = model.SessionStepVerifyEmailOTP
		}
	} else if secondFactorEnforced {
		step = model.SessionStepVerifySecondFactor
	} else {
		completed = true
	}

	var session *model.Session
	var attempt *model.SignInAttempt

	err := database.Connection.Transaction(func(tx *gorm.DB) error {
		var err error
		session, attempt, err = createSession(model.SignInMethodPlain, b.Email, completed, step, tx, email.User.ID)
		if err != nil {
			return err
		}

		attempt.FirstMethodAuthenticated = authenticated
		attempt.SecondMethodAuthenticationRequired = secondFactorEnforced
		attempt.LastActiveOrgID = email.User.LastActiveOrgID
		return tx.Save(attempt).Error
	})

	if err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	var keypair model.DeploymentKeyPair

	if err := database.Connection.Where("deployment_id = ?", d.ID).First(&keypair).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	token, err := signJWT(session.ID, d.Host, time.Now().Add(time.Minute*5), keypair)

	if err != nil {
		println(err.Error())
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	c.Cookie(&fiber.Cookie{
		Name:     "__session",
		Domain:   d.Host,
		Value:    token,
		Path:     "/",
		HTTPOnly: true,
		Secure:   true,
	})

	return handler.SendSuccess(c, session)
}

func validateSignUpRequest(b *SignUpRequest, d model.Deployment) error {
	if d.AuthSettings.FirstName.Required && b.FirstName == "" {
		return fiber.NewError(fiber.StatusBadRequest, "First name is required")
	}
	if d.AuthSettings.LastName.Required && b.LastName == "" {
		return fiber.NewError(fiber.StatusBadRequest, "Last name is required")
	}
	if d.AuthSettings.EmailAddress.Required && b.Email == "" {
		return fiber.NewError(fiber.StatusBadRequest, "Email address is required")
	}
	if d.AuthSettings.Username.Required && b.Username == "" {
		return fiber.NewError(fiber.StatusBadRequest, "Username is required")
	}
	if d.AuthSettings.Password.Required && b.Password == "" {
		return fiber.NewError(fiber.StatusBadRequest, "Password is required")
	}
	if d.AuthSettings.PhoneNumber.Required && b.PhoneNumber == "" {
		return fiber.NewError(fiber.StatusBadRequest, "Phone number is required")
	}
	return nil
}

func SignUp(c *fiber.Ctx) error {
	b, verr := handler.Validate[SignUpRequest](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	d := handler.GetDeployment(c)
	if err := validateSignUpRequest(b, d); err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	if b.Email != "" {
		var email model.UserEmailAddress
		if err := database.Connection.Where("email = ?", b.Email).First(&email).Error; err == nil {
			return handler.SendBadRequest(c, nil, "Email address already exists")
		}
	}

	hashedPassword, err := utils.HashPassword(b.Password)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Error hashing password")
	}

	totpKey, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Wacht",
		AccountName: b.Email,
	})
	if err != nil {
		return handler.SendInternalServerError(c, err, "Error generating TOTP secret")
	}
	totpSecret := totpKey.Secret()

	u := model.User{
		Model:               model.Model{ID: uint(snowflake.ID())},
		FirstName:           b.FirstName,
		LastName:            b.LastName,
		Username:            b.Username,
		Password:            hashedPassword,
		PhoneNumber:         b.PhoneNumber,
		PrimaryEmailAddress: b.Email,
		UserEmailAddresses: []model.UserEmailAddress{{
			Model:     model.Model{ID: uint(snowflake.ID())},
			Email:     b.Email,
			IsPrimary: true,
		}},
		TOTPSecret:         totpSecret,
		SchemaVersion:      model.SchemaVersionV1,
		SecondFactorPolicy: d.AuthSettings.SecondFactorPolicy,
		DeploymentID:       d.ID,
	}

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&u).Error; err != nil {
			return err
		}

		completed := !d.AuthSettings.VerificationPolicy.Email
		_, _, err = createSession(
			model.SignInMethodPlain,
			b.Email,
			completed,
			model.SessionStepVerifyEmailOTP,
			tx,
			u.ID,
		)
		return err
	})

	if err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	passcode, err := totp.GenerateCode(u.TOTPSecret, time.Now())
	if err != nil {
		return handler.SendInternalServerError(c, err, "Error generating passcode")
	}

	fmt.Printf("Generated Passcode for %s: %s\n", u.PrimaryEmailAddress, passcode)

	if err := SendOTP(u.PrimaryEmailAddress , passcode); err != nil {
		return handler.SendInternalServerError(c, err, "Error sending OTP email")
	}

	return handler.SendSuccess(c, u)
}


func AuthMethods(c *fiber.Ctx) error {
	d := handler.GetDeployment(c)
	return handler.SendSuccess(c, d.AuthSettings)
}

func getOAuthConfig(provider model.SSOProvider) *oauth2.Config {
	cred := config.GetDefaultOAuthCredentials(string(provider))
	conf := &oauth2.Config{
		ClientID:     cred.ClientID,
		ClientSecret: cred.ClientSecret,
		RedirectURL:  cred.RedirectURI,
		Scopes:       cred.Scopes,
	}

	switch provider {
	case model.SSOProviderGitHub:
		conf.Endpoint = github.Endpoint
	case model.SSOProviderGoogle:
		conf.Endpoint = google.Endpoint
	case model.SSOProviderMicrosoft:
		conf.Endpoint = microsoft.AzureADEndpoint("")
	}

	return conf
}

func InitSSO(c *fiber.Ctx) error {
	provider := model.SSOProvider(c.Query("provider"))
	if provider == "" {
		return handler.SendBadRequest(c, nil, "Provider is required")
	}

	var attempt *model.SignInAttempt
	var result *model.Session

	err := database.Connection.Transaction(func(tx *gorm.DB) error {
		var err error
		result, attempt, err = createSession(model.SignInMethodSSO, "", false, "", tx, 0)
		if err != nil {
			return err
		}
		attempt.SSOProvider = provider
		return tx.Save(attempt).Error
	})

	if err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	url := utils.GenerateVerificationUrl(provider, *attempt)
	return handler.SendSuccess(c, fiber.Map{
		"oauth_url": url,
		"session":   result,
	})
}

func handleExistingUser(tx *gorm.DB, email *model.UserEmailAddress, token *oauth2.Token, attempt *model.SignInAttempt, deploymentSettings model.AuthSettings) error {
	var connection model.SocialConnection
	for _, sc := range email.User.SocialConnections {
		if sc.Provider == attempt.SSOProvider && sc.EmailAdress == email.Email {
			connection = sc
			break
		}
	}

	if connection.ID == 0 {
		connection = model.SocialConnection{
			Model:        model.Model{ID: uint(snowflake.ID())},
			Provider:     attempt.SSOProvider,
			EmailAdress:  email.Email,
			UserID:       email.User.ID,
			AcessToken:   token.AccessToken,
			RefreshToken: token.RefreshToken,
		}

		if err := tx.Create(&connection).Error; err != nil {
			return err
		}

		attempt.FirstMethodAuthenticated = true
		attempt.SecondMethodAuthenticationRequired = deploymentSettings.SecondFactorPolicy == model.SecondFactorPolicyEnforced
		if attempt.SecondMethodAuthenticationRequired {
			attempt.CurrenStep = model.SessionStepVerifySecondFactor
		} else {
			attempt.Completed = true
		}

		if attempt.Completed {
			signIn := model.SignIn{
				Model:     model.Model{ID: uint(snowflake.ID())},
				SessionID: attempt.SessionID,
				UserID:    email.User.ID,
			}
			if err := tx.Create(&signIn).Error; err != nil {
				return err
			}
		}
	}

	return tx.Save(attempt).Error
}

func SSOCallback(c *fiber.Ctx) error {
	code := c.Query("code")
	deployment := handler.GetDeployment(c)

	if code == "" {
		return handler.SendBadRequest(c, nil, "Code is required")
	}

	var attempt model.SignInAttempt
	if err := database.Connection.Where("id = ?", c.Query("state")).First(&attempt).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Invalid state")
	}

	conf := getOAuthConfig(attempt.SSOProvider)
	token, err := conf.Exchange(c.Context(), code)
	if err != nil || !token.Valid() {
		return handler.SendBadRequest(c, nil, "Invalid code")
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
			return handleExistingUser(tx, &email, token, &attempt, deployment.AuthSettings)
		}

		u := model.User{
			Model:               model.Model{ID: uint(snowflake.ID())},
			PrimaryEmailAddress: user.Email,
			SchemaVersion:       model.SchemaVersionV1,
			SecondFactorPolicy:  deployment.AuthSettings.SecondFactorPolicy,
			DeploymentID:        deployment.ID,
		}

		if err := tx.Create(&u).Error; err != nil {
			return err
		}

		email := model.UserEmailAddress{
			Model:     model.Model{ID: uint(snowflake.ID())},
			Email:     user.Email,
			IsPrimary: true,
			UserID:    u.ID,
		}

		if err := tx.Create(&email).Error; err != nil {
			return err
		}

		connection := model.SocialConnection{
			Model:              model.Model{ID: uint(snowflake.ID())},
			Provider:           attempt.SSOProvider,
			EmailAdress:        user.Email,
			UserID:             u.ID,
			UserEmailAddressID: email.ID,
			AcessToken:         token.AccessToken,
			RefreshToken:       token.RefreshToken,
		}

		return tx.Create(&connection).Error
	})

	if err != nil {
		return handler.SendInternalServerError(c, err, "Something went wrong")
	}

	return handler.SendSuccess(c, fiber.Map{})
}

func SendOTP(email string, otp string) error {
  smtpHost := "email-smtp.ap-south-1.amazonaws.com"
	smtpPort := "587"
	username := "AKIAXYKJVFAQR4XQ3PGA"
	password := "BJTY7M850mnFoKPvhzxFJpBPhpQxfvaXGv4MY7GWdWuw"

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
	err := smtp.SendMail(smtpServer, auth, username, []string{email}, msg)
	if err != nil {
		return fmt.Errorf("failed to send email to %s: %w", email, err)
	}

  return nil
}


// func VerifyOTP(secret, passcode string) (bool, error) {
// 	valid := totp.Validate(passcode, secret)
// 	if !valid {
// 		return false, fiber.NewError(fiber.StatusBadRequest, "Invalid passcode")
// 	}
// 	return true, nil
// }

func VerifyOTP(c *fiber.Ctx) error {
	b, verr := handler.Validate[VerifyOTPRequest](c)
	if verr != nil {
			return handler.SendBadRequest(c, verr, "Bad request body")
	}

	var email model.UserEmailAddress
	if err := database.Connection.Where("email = ?", b.Email).First(&email).Error; err != nil {
			return handler.SendNotFound(c, nil, "Email not found")
	}

	valid := totp.Validate(b.Passcode, email.User.TOTPSecret)
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



