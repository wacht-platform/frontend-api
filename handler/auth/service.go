package auth

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aymerick/raymond"
	"github.com/godruoyi/go-snowflake"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/config"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/utils"
	"github.com/ua-parser/uap-go/uaparser"
	"github.com/wneessen/go-mail"
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

func (s *AuthService) FindUserByEmail(
	email string,
) (*model.UserEmailAddress, error) {
	var userEmail model.UserEmailAddress
	if res := s.db.Where(&model.UserEmailAddress{EmailAddress: email}).Joins("User").Preload("User", func(db *gorm.DB) *gorm.DB {
		return db.Select("*")
	}).First(&userEmail); res.RowsAffected == 0 {
		return nil, handler.ErrUserNotFound
	} else if res.Error != nil {
		return nil, res.Error
	}

	return &userEmail, nil
}

func (s *AuthService) FindUserByEmailID(
	emailId uint64,
) (*model.UserEmailAddress, error) {
	var userEmail model.UserEmailAddress
	if res := s.db.Where(&model.UserEmailAddress{Model: model.Model{ID: emailId}}).Joins("User").Preload("User", func(db *gorm.DB) *gorm.DB {
		return db.Select("*")
	}).First(&userEmail); res.RowsAffected == 0 {
		return nil, handler.ErrUserNotFound
	} else if res.Error != nil {
		return nil, res.Error
	}
	return &userEmail, nil
}

func (s *AuthService) ValidateUserStatus(
	user *model.UserEmailAddress,
) error {
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

	if !authenticated &&
		authSettings.FirstFactor == model.FirstFactorEmailOTP {
		steps = append(steps, model.SignInAttemptStepVerifyEmailOTP)
	}

	if secondFactorEnforced {
		steps = append(
			steps,
			model.SignInAttemptStepVerifySecondFactor,
		)
	}

	completed = len(steps) == 0

	return steps, completed
}

func (s *AuthService) CreateSignInAttempt(
	userID uint64,
	identifierID uint64,
	sessionID uint64,
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

func (s *AuthService) ValidateSignUpRequest(
	b *SignUpRequest,
	d model.Deployment,
) error {
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
	if d.AuthSettings.PhoneNumber.Required && b.PhoneNumber == "" {
		return handler.ErrRequiredField("Phone number")
	}
	return nil
}

func (s *AuthService) CreateUser(
	b *SignUpRequest,
	hashedPassword string,
	deploymentID uint64,
	secondFactorPolicy model.SecondFactorPolicy,
	otpSecret string,
	verified bool,
) model.User {
	emailID := snowflake.ID()
	u := model.User{
		Model:                 model.Model{ID: snowflake.ID()},
		FirstName:             b.FirstName,
		LastName:              b.LastName,
		Username:              b.Username,
		Password:              hashedPassword,
		PrimaryEmailAddressID: &emailID,
		UserEmailAddresses: []model.UserEmailAddress{{
			Model:                model.Model{ID: emailID},
			EmailAddress:         b.Email,
			IsPrimary:            true,
			Verified:             verified,
			VerificationStrategy: model.Otp,
			VerifiedAt:           time.Now(),
			DeploymentID:         deploymentID,
		}},
		SchemaVersion:      model.SchemaVersionV1,
		SecondFactorPolicy: secondFactorPolicy,
		DeploymentID:       deploymentID,
		OtpSecret:          otpSecret,
	}

	if b.PhoneNumber != "" {
		phoneNumberID := snowflake.ID()
		u.UserPhoneNumbers = append(
			u.UserPhoneNumbers,
			model.UserPhoneNumber{
				Model:       model.Model{ID: phoneNumberID},
				PhoneNumber: b.PhoneNumber,
				Verified:    false,
			},
		)
		u.PrimaryPhoneNumberID = &phoneNumberID
	}

	return u
}

func (s *AuthService) CreateSocialConnection(
	userID uint64,
	emailID uint64,
	provider model.SocialConnectionProvider,
	email string,
	token *oauth2.Token,
) model.SocialConnection {
	return model.SocialConnection{
		Model:              model.Model{ID: snowflake.ID()},
		Provider:           provider,
		EmailAddress:       email,
		UserID:             userID,
		UserEmailAddressID: emailID,
		AccessToken:        token.AccessToken,
		RefreshToken:       token.RefreshToken,
	}
}

func (s *AuthService) HandleExistingUser(
	tx *gorm.DB,
	email *model.UserEmailAddress,
	token *oauth2.Token,
	attempt *model.SignInAttempt,
	deploymentSettings model.DeploymentAuthSettings,
) (*model.Signin, error) {
	var connection model.SocialConnection
	for _, sc := range email.User.SocialConnections {
		if sc.Provider == attempt.SSOProvider &&
			sc.EmailAddress == email.EmailAddress {
			connection = sc
			break
		}
	}

	if connection.ID == 0 {
		connection = s.CreateSocialConnection(
			email.User.ID,
			email.ID,
			attempt.SSOProvider,
			email.EmailAddress,
			token,
		)

		if err := tx.Create(&connection).Error; err != nil {
			return nil, err
		}
	}

	// Always create a signin for SSO authentication
	signIn := model.NewSignIn(
		attempt.SessionID,
		email.User.ID,
	)
	if err := tx.Create(&signIn).Error; err != nil {
		return nil, err
	}

	return signIn, nil
}

func (s *AuthService) VerifyPassword(
	storedHash, password string,
) (bool, error) {
	return utils.ComparePassword(storedHash, password)
}

func (s *AuthService) HashPassword(password string) (string, error) {
	return utils.HashPassword(password)
}

func (s *AuthService) CheckEmailExists(email string) bool {
	var count int64
	s.db.Model(&model.UserEmailAddress{}).
		Where("email = ?", email).
		Count(&count)
	return count > 0
}

func (s *AuthService) CheckUsernameExists(username string) bool {
	var count int64
	s.db.Model(&model.User{}).
		Where("username = ?", username).
		Count(&count)
	return count > 0
}

func (s *AuthService) CheckUserphoneExists(phone string) bool {
	var count int64
	s.db.Model(&model.UserPhoneNumber{}).
		Where("phone_number = ?", phone).
		Count(&count)
	return count > 0
}

func getOAuthConfigForDeployment(
	provider model.SocialConnectionProvider,
	deployment *model.Deployment,
) (*oauth2.Config, error) {
	cred, err := config.GetDeploymentOAuthCredentials(deployment, provider)
	if err != nil {
		return nil, err
	}

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

	return conf, nil
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

func (s *AuthService) GetSignInAttempt(
	signInAttempt uint64,
) (model.SignInAttempt, error) {
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

	url := fmt.Sprintf(
		"https://api.pwnedpasswords.com/range/%s",
		prefix,
	)
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
		return false, fmt.Errorf(
			"failed to read HIBP API response: %w",
			err,
		)
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

	hasSymbol := regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).
		MatchString(password)
	if !hasSymbol {
		return ErrInvalidPassword
	}
	return nil
}

func (s *AuthService) SendEmailOTPVerification(
	email string,
	otp string,
	deployment model.Deployment,
) error {
	smtpHost := os.Getenv("SES_SMTP_HOST")
	username := os.Getenv("SES_SMTP_USERNAME")
	password := os.Getenv("SES_SMTP_PASSWORD")
	from := fmt.Sprintf("%s@%s", deployment.EmailTemplates.VerificationCodeTemplate.TemplateFrom, deployment.MailFromHost)

	ctx := map[string]string{
		"app_name": deployment.UISettings.AppName,
		"app_logo": deployment.UISettings.LogoImageURL,
		"code":     otp,
	}

	subject, err := raymond.Render(deployment.EmailTemplates.VerificationCodeTemplate.TemplateSubject, ctx)
	if err != nil {
		return err
	}

	tpl := fmt.Sprintf(`<html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>%s</title></head><body>%s</body></html>`, subject, deployment.EmailTemplates.VerificationCodeTemplate.TemplateData)

	htmlBody, err := raymond.Render(tpl, ctx)
	if err != nil {
		return err
	}

	message := mail.NewMsg()
	mail.WithNoDefaultUserAgent()(message)
	message.From(from)
	message.To(email)
	message.Subject(subject)
	message.SetBodyString(mail.TypeTextHTML, htmlBody)

	smtpClient, err := mail.NewClient(
		smtpHost,
		mail.WithPort(2587),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername(username),
		mail.WithPassword(password),
	)

	if err != nil {
		return err
	}

	err = smtpClient.DialAndSend(message)

	return err
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
	if d.AuthSettings.VerificationPolicy.PhoneNumber &&
		b.PhoneNumber != "" {
		steps = append(steps, model.SignupAttemptStepVerifyPhone)
	}

	attempt := &model.SignupAttempt{
		Model: model.Model{
			ID: snowflake.ID(),
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

func (s *AuthService) StoreOTPInCache(key string, otp string) error {
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

func (s *AuthService) GetSignupAttempt(
	signupAttempt uint64,
) (*model.SignupAttempt, error) {
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
		model.SecondFactorPolicyNone,
		otpSecret,
		true,
	)
	return &user, nil
}

func (s *AuthService) CreateSignin(
	userID uint64,
	sessionID uint64,
	ctx *fiber.Ctx,
) *model.Signin {
	signIn := model.NewSignIn(sessionID, userID)
	ua := ctx.Get("User-Agent")

	var ip string
	if len(ctx.IPs()) > 0 {
		ip = ctx.IPs()[0]
	} else {
		ip = ctx.IP()
	}

	resp, err := http.Get(
		"http://ip-api.com/json/" + ip + "?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query",
	)
	if err != nil {
		return signIn
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return signIn
	}

	var ipLocation IPLocation
	err = json.Unmarshal(body, &ipLocation)
	if err != nil {
		return signIn
	}

	if ipLocation.Status != "success" {
		return signIn
	}

	parsedUa := uaparser.NewFromSaved().Parse(ua)

	signIn.Browser = parsedUa.UserAgent.Family
	signIn.Device = parsedUa.Device.Family
	signIn.City = ipLocation.City
	signIn.Region = ipLocation.RegionName
	signIn.Country = ipLocation.Country
	signIn.CountryCode = ipLocation.CountryCode
	signIn.RegionCode = ipLocation.Region
	signIn.IpAddress = ip
	signIn.LastActiveAt = time.Now().Format(time.RFC3339)

	return signIn
}
