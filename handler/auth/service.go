package auth

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"regexp"
	"strings"

	"github.com/godruoyi/go-snowflake"
	"github.com/ilabs/wacht-fe/config"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/utils"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/linkedin"
	"golang.org/x/oauth2/microsoft"
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
		return nil, ErrUserNotFound
	} else if res.Error != nil {
		return nil, res.Error
	}
	return &userEmail, nil
}

func (s *AuthService) ValidateUserStatus(user *model.UserEmailAddress) error {
	if user.User.Disabled {
		return ErrUserDisabled
	}
	return nil
}

func (s *AuthService) DetermineAuthenticationStep(verified, authenticated, secondFactorEnforced bool, authSettings model.AuthSettings) (model.CurrentSessionStep, bool) {
	var step model.CurrentSessionStep
	completed := false

	if !verified {
		step = model.SessionStepVerifyEmail
	} else if !authenticated && authSettings.FirstFactor == model.FirstFactorEmailOTP {
		step = model.SessionStepVerifyEmailOTP
	} else if secondFactorEnforced {
		step = model.SessionStepVerifySecondFactor
	} else {
		completed = true
	}

	return step, completed
}

func (s *AuthService) CreateSignInAttempt(
	userID uint,
	identifierID uint,
	sessionID uint,
	method model.SignInMethod,
	authenticated bool,
	secondFactorEnforced bool,
	step model.CurrentSessionStep,
	completed bool,
	lastActiveOrgID uint,
) *model.SignInAttempt {
	attempt := model.NewSignInAttempt(method)
	attempt.CurrentStep = step
	attempt.IdentifierID = identifierID
	attempt.Completed = completed
	attempt.UserID = userID
	attempt.SessionID = sessionID
	attempt.FirstMethodAuthenticated = authenticated
	attempt.SecondMethodAuthenticationRequired = secondFactorEnforced
	return attempt
}

func (s *AuthService) ValidateSignUpRequest(b *SignUpRequest, d model.Deployment) error {
	if d.AuthSettings.FirstName.Required && b.FirstName == "" {
		return ErrRequiredField("First name")
	}
	if d.AuthSettings.LastName.Required && b.LastName == "" {
		return ErrRequiredField("Last name")
	}
	if d.AuthSettings.EmailAddress.Required && b.Email == "" {
		return ErrRequiredField("Email address")
	}
	if d.AuthSettings.Username.Required && b.Username == "" {
		return ErrRequiredField("Username")
	}
	if d.AuthSettings.Password.Required && b.Password == "" {
		return ErrRequiredField("Password")
	}
	if d.AuthSettings.PhoneNumber.Required && b.PhoneNumber == "" {
		return ErrRequiredField("Phone number")
	}
	return nil
}

func (s *AuthService) CreateUser(b *SignUpRequest, hashedPassword string, deploymentID uint, secondFactorPolicy model.SecondFactorPolicy, otpSecret string) model.User {
	emailID := uint(snowflake.ID())
	u := model.User{
		Model:                 model.Model{ID: uint(snowflake.ID())},
		FirstName:             b.FirstName,
		LastName:              b.LastName,
		Username:              b.Username,
		Password:              hashedPassword,
		PrimaryEmailAddressID: emailID,
		UserEmailAddresses: []*model.UserEmailAddress{{
			Model:     model.Model{ID: emailID},
			Email:     b.Email,
			IsPrimary: true,
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
	}

	return u
}

func (s *AuthService) CreateSocialConnection(userID uint, emailID uint, provider model.SSOProvider, email string, token *oauth2.Token) model.SocialConnection {
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

func (s *AuthService) HandleExistingUser(tx *gorm.DB, email *model.UserEmailAddress, token *oauth2.Token, attempt *model.SignInAttempt, deploymentSettings model.AuthSettings) error {
	var connection model.SocialConnection
	for _, sc := range email.User.SocialConnections {
		if sc.Provider == attempt.SSOProvider && sc.EmailAdress == email.Email {
			connection = *sc
			break
		}
	}

	if connection.ID == 0 {
		connection = s.CreateSocialConnection(email.User.ID, email.ID, attempt.SSOProvider, email.Email, token)

		if err := tx.Create(&connection).Error; err != nil {
			return err
		}

		attempt.FirstMethodAuthenticated = true
		attempt.SecondMethodAuthenticationRequired = deploymentSettings.SecondFactorPolicy == model.SecondFactorPolicyEnforced
		if attempt.SecondMethodAuthenticationRequired {
			attempt.CurrentStep = model.SessionStepVerifySecondFactor
		} else {
			attempt.Completed = true
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
	case model.SSOProviderFacebook:
		conf.Endpoint = facebook.Endpoint
	case model.SSOProviderLinkedIn:
		conf.Endpoint = linkedin.Endpoint
	case model.SSOProviderX:
		conf.Endpoint = config.XOAuthEndpoint
	case model.SSOProviderApple:
		conf.Endpoint = config.AppleOAuthEndpoint
	case model.SSOProviderDiscord:
		conf.Endpoint = config.DiscordOAuthEndpoint
	}

	return conf
}

func (s *AuthService) CheckIdentifierAvailability(identifier string, identifierType string) (bool, error) {
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
	ErrInvalidPassword := errors.New("password must be 6-125 characters long, contain at least one number, and one symbol")

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
