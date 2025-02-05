package auth

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"regexp"
	"strings"
	"time"

	"github.com/godruoyi/go-snowflake"
	"github.com/ilabs/wacht-fe/config"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/utils"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/linkedin"
	"golang.org/x/oauth2/microsoft"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type AuthService struct {
	db *gorm.DB
}

func NewAuthService() *AuthService {
	return &AuthService{
		db: database.Connection,
	}
}

func (s *AuthService) FindUserByEmail(email string) (*model.UserEmailAddress, error) {
	var userEmail model.UserEmailAddress
	if res := s.db.Where(&model.UserEmailAddress{Email: email}).Joins("User").First(&userEmail); res.RowsAffected == 0 {
		return nil, handler.ErrUserNotFound
	} else if res.Error != nil {
		return nil, res.Error
	}

	return &userEmail, nil
}

func (s *AuthService) FindUserByEmailID(emailId uint) (*model.UserEmailAddress, error) {
	var userEmail model.UserEmailAddress
	if res := s.db.Where(&model.UserEmailAddress{Model: model.Model{ID: emailId}}).Joins("User").First(&userEmail); res.RowsAffected == 0 {
		return nil, handler.ErrUserNotFound
	} else if res.Error != nil {
		return nil, res.Error
	}
	return &userEmail, nil
}

func (s *AuthService) ValidateUserStatus(user *model.UserEmailAddress) error {
	if user.User.Disabled {
		return handler.ErrUserDisabled
	}
	return nil
}

func (s *AuthService) DetermineAuthenticationStep(
	verified, authenticated, secondFactorEnforced bool,
	authSettings model.DeploymentAuthSettings,
) ([]model.SignInAttemptStep, bool) {
	var steps []model.SignInAttemptStep
	completed := false

	if !verified && authenticated {
		steps = append(steps, model.SignInAttemptStepVerifyEmail)
	}

	if !authenticated && authSettings.FirstFactor == model.FirstFactorEmailOTP {
		steps = append(steps, model.SignInAttemptStepVerifyEmailOTP)
	}

	if secondFactorEnforced {
		steps = append(steps, model.SignInAttemptStepVerifySecondFactor)
	}

	completed = len(steps) == 0

	return steps, completed
}

func (s *AuthService) CreateSignInAttempt(
	userID uint,
	identifierID uint,
	sessionID uint,
	method model.SignInMethod,
	steps []model.SignInAttemptStep,
	completed bool,
) *model.SignInAttempt {
	attempt := model.NewSignInAttempt(method)
	if len(steps) > 0 {
		attempt.CurrentStep = steps[0]
	}
	attempt.RemainingSteps = datatypes.NewJSONSlice(steps)
	attempt.IdentifierID = identifierID
	attempt.Completed = completed
	attempt.UserID = userID
	attempt.SessionID = sessionID
	return attempt
}

func (s *AuthService) ValidateSignUpRequest(b *SignUpRequest, d model.Deployment) error {
	if d.AuthSettings.FirstName.Required && b.FirstName == "" {
		return handler.ErrRequiredField("First name")
	}
	if d.AuthSettings.LastName.Required && b.LastName == "" {
		return handler.ErrRequiredField("Last name")
	}
	if d.AuthSettings.EmailAddress.Required && b.Email == "" {
		return handler.ErrRequiredField("Email address")
	}
	if d.AuthSettings.Username.Required && b.Username == "" {
		return handler.ErrRequiredField("Username")
	}
	if d.AuthSettings.Password.Required && b.Password == "" {
		return handler.ErrRequiredField("Password")
	}
	if d.AuthSettings.PhoneNumber.Required && b.PhoneNumber == "" {
		return handler.ErrRequiredField("Phone number")
	}
	return nil
}

func (s *AuthService) CreateUser(
	b *SignUpRequest,
	hashedPassword string,
	deploymentID uint,
	secondFactorPolicy model.SecondFactorPolicy,
	otpSecret string,
	verified bool,
) model.User {
	emailID := uint(snowflake.ID())
	u := model.User{
		Model:                 model.Model{ID: uint(snowflake.ID())},
		FirstName:             b.FirstName,
		LastName:              b.LastName,
		Username:              b.Username,
		Password:              hashedPassword,
		PrimaryEmailAddressID: &emailID,
		UserEmailAddresses: []*model.UserEmailAddress{{
			Model:                model.Model{ID: emailID},
			Email:                b.Email,
			IsPrimary:            true,
			Verified:             verified,
			VerificationStrategy: model.Otp,
			VerifiedAt:           time.Now(),
		}},
		SchemaVersion:      model.SchemaVersionV1,
		SecondFactorPolicy: secondFactorPolicy,
		DeploymentID:       deploymentID,
		OtpSecret:          otpSecret,
	}

	if b.PhoneNumber != "" {
		phoneNumberID := uint(snowflake.ID())
		u.UserPhoneNumbers = append(u.UserPhoneNumbers, &model.UserPhoneNumber{
			Model:       model.Model{ID: phoneNumberID},
			PhoneNumber: b.PhoneNumber,
			Verified:    false,
		})
		u.PrimaryPhoneNumberID = &phoneNumberID
	}

	return u
}

func (s *AuthService) CreateSocialConnection(
	userID uint,
	emailID uint,
	provider model.SocialConnectionProvider,
	email string,
	token *oauth2.Token,
) model.SocialConnection {
	return model.SocialConnection{
		Model:              model.Model{ID: uint(snowflake.ID())},
		Provider:           provider,
		EmailAdress:        email,
		UserID:             userID,
		UserEmailAddressID: emailID,
		AcessToken:         token.AccessToken,
		RefreshToken:       token.RefreshToken,
	}
}

func (s *AuthService) HandleExistingUser(
	tx *gorm.DB,
	email *model.UserEmailAddress,
	token *oauth2.Token,
	attempt *model.SignInAttempt,
	deploymentSettings model.DeploymentAuthSettings,
) error {
	var connection model.SocialConnection
	for _, sc := range email.User.SocialConnections {
		if sc.Provider == attempt.SSOProvider && sc.EmailAdress == email.Email {
			connection = *sc
			break
		}
	}

	if connection.ID == 0 {
		connection = s.CreateSocialConnection(
			email.User.ID,
			email.ID,
			attempt.SSOProvider,
			email.Email,
			token,
		)

		if err := tx.Create(&connection).Error; err != nil {
			return err
		}

		if attempt.Completed {
			signIn := model.NewSignIn(attempt.SessionID, email.User.ID)
			if err := tx.Create(&signIn).Error; err != nil {
				return err
			}
		}
	}

	return tx.Save(attempt).Error
}

func (s *AuthService) VerifyPassword(storedHash, password string) (bool, error) {
	return utils.ComparePassword(storedHash, password)
}

func (s *AuthService) HashPassword(password string) (string, error) {
	return utils.HashPassword(password)
}

func (s *AuthService) CheckEmailExists(email string) bool {
	var count int64
	s.db.Model(&model.UserEmailAddress{}).Where("email = ?", email).Count(&count)
	return count > 0
}

func (s *AuthService) CheckUsernameExists(username string) bool {
	var count int64
	s.db.Model(&model.User{}).Where("username = ?", username).Count(&count)
	return count > 0
}

func (s *AuthService) CheckUserphoneExists(phone string) bool {
	var count int64
	s.db.Model(&model.UserPhoneNumber{}).Where("phone_number = ?", phone).Count(&count)
	return count > 0
}

func getOAuthConfig(provider model.SocialConnectionProvider) *oauth2.Config {
	cred := config.GetDefaultOAuthCredentials(string(provider))
	conf := &oauth2.Config{
		ClientID:     cred.ClientID,
		ClientSecret: cred.ClientSecret,
		RedirectURL:  cred.RedirectURI,
		Scopes:       cred.Scopes,
	}

	switch provider {
	case model.SocialConnectionProviderGitHub:
		conf.Endpoint = github.Endpoint
	case model.SocialConnectionProviderGoogle:
		conf.Endpoint = google.Endpoint
	case model.SocialConnectionProviderMicrosoft:
		conf.Endpoint = microsoft.AzureADEndpoint("")
	case model.SocialConnectionProviderFacebook:
		conf.Endpoint = facebook.Endpoint
	case model.SocialConnectionProviderLinkedIn:
		conf.Endpoint = linkedin.Endpoint
	case model.SocialConnectionProviderX:
		conf.Endpoint = config.XOAuthEndpoint
	case model.SocialConnectionProviderApple:
		conf.Endpoint = config.AppleOAuthEndpoint
	case model.SocialConnectionProviderDiscord:
		conf.Endpoint = config.DiscordOAuthEndpoint
	}

	return conf
}

func (s *AuthService) CheckIdentifierAvailability(
	identifier string,
	identifierType string,
) (bool, error) {
	if identifierType == "email" {
		return s.CheckEmailExists(identifier), nil
	} else if identifierType == "username" {
		return s.CheckUsernameExists(identifier), nil
	}
	return false, errors.New("invalid identifier type")
}

func (s *AuthService) GetSignInAttempt(signInAttempt uint) (model.SignInAttempt, error) {
	var attempt model.SignInAttempt
	if err := s.db.Where("id = ?", signInAttempt).First(&attempt).Error; err != nil {
		log.Println(err, signInAttempt)
		return model.SignInAttempt{}, err
	}
	return attempt, nil
}

func (s *AuthService) PawnedPassword(password string) (bool, error) {
	hasher := sha1.New()
	hasher.Write([]byte(password))
	hash := hex.EncodeToString(hasher.Sum(nil))

	prefix := strings.ToUpper(hash[:5])
	suffix := strings.ToUpper(hash[5:])

	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)
	resp, err := http.Get(url)
	if err != nil {
		return false, fmt.Errorf("failed to query HIBP API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, errors.New("unexpected response from HIBP API")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read HIBP API response: %w", err)
	}

	hashes := strings.Split(string(body), "\n")
	for _, line := range hashes {
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		if parts[0] == suffix {
			return true, nil
		}
	}

	return false, nil
}

func (s *AuthService) ValidatePassword(password string) error {
	ErrInvalidPassword := errors.New(
		"password must be 6-125 characters long, contain at least one number, and one symbol",
	)

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

func (s *AuthService) SendEmailOTPVerification(email string, otp string) error {
	smtpHost := "smtp.zeptomail.in"
	smtpPort := "587"
	username := "emailapikey"
	password := "PHtE6r1cR7rsgmEsoEMI4vPsRMWlZ41/r75kK1EWstkUA6NRGE0H+dt9kmPkoxopA6NGEvKZyNlgsrLK5rmDIT7qMjtEWWqyqK3sx/VYSPOZsbq6x00VtFoedELVU4TodNJj0Czfs97bNA=="
	from := "notifications@wacht.tech"

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

	fromstr := fmt.Sprintf("From: Security Notifications <%s>\r\n", from)
	subject := "Subject: Your OTP Code\r\n"
	contentType := "MIME-Version: 1.0\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n"
	msg := []byte(fromstr + subject + contentType + htmlBody)

	smtpServer := fmt.Sprintf("%s:%s", smtpHost, smtpPort)
	err := smtp.SendMail(smtpServer, auth, from, []string{email}, msg)

	if err != nil {
		return fmt.Errorf("failed to send email to %s: %w", email, err)
	}

	return nil
}

func (s *AuthService) CreateSignupAttempt(
	b *SignUpRequest,
	hashedPassword string,
	session *model.Session,
	d model.Deployment,
) (*model.SignupAttempt, error) {
	var requiredFields []string
	if d.AuthSettings.FirstName.Required {
		requiredFields = append(requiredFields, "first_name")
	}
	if d.AuthSettings.LastName.Required {
		requiredFields = append(requiredFields, "last_name")
	}
	if d.AuthSettings.EmailAddress.Required {
		requiredFields = append(requiredFields, "email")
	}
	if d.AuthSettings.Username.Required {
		requiredFields = append(requiredFields, "username")
	}
	if d.AuthSettings.PhoneNumber.Required {
		requiredFields = append(requiredFields, "phone_number")
	}

	var missingFields []string
	for _, field := range requiredFields {
		switch field {
		case "first_name":
			if b.FirstName == "" {
				missingFields = append(missingFields, field)
			}
		case "last_name":
			if b.LastName == "" {
				missingFields = append(missingFields, field)
			}
		case "email":
			if b.Email == "" {
				missingFields = append(missingFields, field)
			}
		case "username":
			if b.Username == "" {
				missingFields = append(missingFields, field)
			}
		case "phone_number":
			if b.PhoneNumber == "" {
				missingFields = append(missingFields, field)
			}
		}
	}

	var steps []model.SignupAttemptStep
	if d.AuthSettings.VerificationPolicy.Email && b.Email != "" {
		steps = append(steps, model.SignupAttemptStepVerifyEmail)
	}
	if d.AuthSettings.VerificationPolicy.PhoneNumber && b.PhoneNumber != "" {
		steps = append(steps, model.SignupAttemptStepVerifyPhone)
	}

	attempt := &model.SignupAttempt{
		Model: model.Model{
			ID: uint(snowflake.ID()),
		},
		SessionID:      session.ID,
		FirstName:      b.FirstName,
		LastName:       b.LastName,
		Email:          b.Email,
		Username:       b.Username,
		PhoneNumber:    b.PhoneNumber,
		Password:       hashedPassword,
		RequiredFields: datatypes.NewJSONSlice(requiredFields),
		MissingFields:  datatypes.NewJSONSlice(missingFields),
		RemainingSteps: datatypes.NewJSONSlice(steps),
	}

	if len(steps) > 0 {
		attempt.CurrentStep = steps[0]
	}

	return attempt, nil
}

const (
	otpExpirationTime = 5 * time.Minute
)

func (s *AuthService) StoreOTPInRedis(key string, otp string) error {
	return database.Cache.Set(
		context.Background(),
		fmt.Sprintf("otp:%s", key),
		otp,
		otpExpirationTime,
	).Err()
}

func (s *AuthService) GetOTPFromRedis(key string) (string, error) {
	return database.Cache.Get(
		context.Background(),
		fmt.Sprintf("otp:%s", key),
	).Result()
}

func (s *AuthService) DeleteOTPFromRedis(key string) error {
	return database.Cache.Del(
		context.Background(),
		fmt.Sprintf("otp:%s", key),
	).Err()
}

func (s *AuthService) GetSignupAttempt(signupAttempt uint) (*model.SignupAttempt, error) {
	var attempt model.SignupAttempt
	if err := s.db.Where("id = ?", signupAttempt).First(&attempt).Error; err != nil {
		return nil, err
	}
	return &attempt, nil
}

func (s *AuthService) CreateVerifiedUser(
	attempt *model.SignupAttempt,
	d model.Deployment,
	otpSecret string,
) (*model.User, error) {
	b := &SignUpRequest{
		FirstName:   attempt.FirstName,
		LastName:    attempt.LastName,
		Username:    attempt.Username,
		Email:       attempt.Email,
		PhoneNumber: attempt.PhoneNumber,
	}

	user := s.CreateUser(
		b,
		attempt.Password,
		d.ID,
		d.AuthSettings.SecondFactorPolicy,
		otpSecret,
		true,
	)
	return &user, nil
}
