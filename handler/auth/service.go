package auth

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"slices"

	"github.com/godruoyi/go-snowflake"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/config"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/service"
	"github.com/ilabs/wacht-fe/utils"
	"github.com/ua-parser/uap-go/uaparser"
	"golang.org/x/oauth2"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type AuthService struct {
	db   *gorm.DB
	nats *service.NatsService
}

func NewAuthService() *AuthService {
	natsService, err := service.NewNatsService()
	if err != nil {
		// Log error and panic - NATS is required
		panic(fmt.Sprintf("Failed to initialize NATS service: %v", err))
	}
	
	return &AuthService{
		db:   database.Connection,
		nats: natsService,
	}
}

func (s *AuthService) FindUserByEmail(
	email string,
) (*model.UserEmailAddress, error) {
	var userEmail model.UserEmailAddress
	if res := s.db.Where(&model.UserEmailAddress{EmailAddress: email}).Joins("User").First(&userEmail); res.RowsAffected == 0 {
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
	if res := s.db.Where(&model.UserEmailAddress{Model: model.Model{ID: emailId}}).Joins("User").First(&userEmail); res.RowsAffected == 0 {
		return nil, handler.ErrUserNotFound
	} else if res.Error != nil {
		return nil, res.Error
	}
	return &userEmail, nil
}

func (s *AuthService) FindUserByPhoneNumber(
	phoneNumber string,
) (*model.UserPhoneNumber, error) {
	var userPhone model.UserPhoneNumber
	if res := s.db.Where(&model.UserPhoneNumber{PhoneNumber: phoneNumber}).Joins("User").First(&userPhone); res.RowsAffected == 0 {
		return nil, handler.ErrUserNotFound
	} else if res.Error != nil {
		return nil, res.Error
	}

	return &userPhone, nil
}

func (s *AuthService) FindUserByPhoneNumberID(
	phoneId uint64,
) (*model.UserPhoneNumber, error) {
	var userPhone model.UserPhoneNumber
	if res := s.db.Where(&model.UserPhoneNumber{Model: model.Model{ID: phoneId}}).Joins("User").First(&userPhone); res.RowsAffected == 0 {
		return nil, handler.ErrUserNotFound
	} else if res.Error != nil {
		return nil, res.Error
	}
	return &userPhone, nil
}

func (s *AuthService) FindUserByUsername(
	username string,
) (*model.User, error) {
	var user model.User
	if res := s.db.Where(&model.User{Username: username}).First(&user); res.RowsAffected == 0 {
		return nil, handler.ErrUserNotFound
	} else if res.Error != nil {
		return nil, res.Error
	}
	return &user, nil
}

func (s *AuthService) ValidateUserStatus(
	user *model.UserEmailAddress,
) error {
	if user.User.Disabled {
		return handler.ErrUserDisabled
	}
	return nil
}

func (s *AuthService) ValidatePhoneUserStatus(
	user *model.UserPhoneNumber,
) error {
	if user.User.Disabled {
		return handler.ErrUserDisabled
	}
	return nil
}

func (s *AuthService) ValidateUsernameUserStatus(
	user *model.User,
) error {
	if user.Disabled {
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

func (s *AuthService) DeterminePhoneAuthenticationStep(
	verified, authenticated, secondFactorEnforced bool,
	authSettings model.DeploymentAuthSettings,
) ([]model.SignInAttemptStep, bool) {
	var steps []model.SignInAttemptStep
	completed := false

	if !verified && authenticated {
		steps = append(steps, model.SignInAttemptStepVerifyPhone)
	}

	if !authenticated &&
		authSettings.FirstFactor == model.FirstFactorPhoneOTP {
		steps = append(steps, model.SignInAttemptStepVerifyPhoneOTP)
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

func (s *AuthService) MaskPhoneNumber(phoneNumber string) string {
	if len(phoneNumber) < 4 {
		return phoneNumber
	}
	masked := strings.Repeat("*", len(phoneNumber)-4) + phoneNumber[len(phoneNumber)-4:]
	return masked
}

func (s *AuthService) DetermineMagicLinkAuthenticationStep(
	verified, authenticated, secondFactorEnforced bool,
	authSettings model.DeploymentAuthSettings,
) ([]model.SignInAttemptStep, bool) {
	var steps []model.SignInAttemptStep
	completed := false

	if !verified && authenticated {
		steps = append(steps, model.SignInAttemptStepVerifyEmail)
	}

	if !authenticated &&
		authSettings.FirstFactor == model.FirstFactorMagicLink {
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
	userID *uint64,
	identifierID *uint64,
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
	attempt.FirstMethodAuthenticated = userID != nil

	if slices.Contains(steps, model.SignInAttemptStepVerifySecondFactor) {
		attempt.SecondMethodAuthenticationRequired = true
		if userID != nil {
			attempt.Available2FAMethods = datatypes.NewJSONSlice(s.GetAvailable2FAMethods(*userID))
		}
	}

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

	if b.Email != "" {
		if err := s.ValidateEmailRestrictions(b.Email, d.Restrictions); err != nil {
			return err
		}
	}

	if b.PhoneNumber != "" {
		if err := s.ValidatePhoneRestrictions(b.PhoneNumber, d.Restrictions); err != nil {
			return err
		}
	}

	if err := s.ValidateBannedKeywords(b, d.Restrictions); err != nil {
		return err
	}

	return nil
}

func (s *AuthService) CreateUser(
	b *SignUpRequest,
	hashedPassword string,
	deploymentID uint64,
	secondFactorPolicy model.SecondFactorPolicy,
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

	if email.User.SecondFactorPolicy == model.SecondFactorPolicyEnforced {
		attempt.UserID = &email.User.ID
		attempt.IdentifierID = &email.ID
		attempt.FirstMethodAuthenticated = true
		attempt.SecondMethodAuthenticationRequired = true
		attempt.CurrentStep = model.SignInAttemptStepVerifySecondFactor
		attempt.RemainingSteps = datatypes.NewJSONSlice([]model.SignInAttemptStep{
			model.SignInAttemptStepVerifySecondFactor,
		})
		attempt.Available2FAMethods = datatypes.NewJSONSlice(s.GetAvailable2FAMethods(email.User.ID))
		return nil, nil
	}

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

func (s *AuthService) SendSignupVerificationEmail(
	signupAttemptID uint64,
	email string,
	code string,
	deployment model.Deployment,
) error {
	return s.nats.SendVerificationEmail(deployment.ID, 0, email, code)
}

func (s *AuthService) SendSigninVerificationEmail(
	userID uint64,
	email string,
	code string,
	deployment model.Deployment,
) error {
	return s.nats.SendVerificationEmail(deployment.ID, userID, email, code)
}

func (s *AuthService) SendPasswordResetEmail(
	userID uint64,
	email string,
	code string,
	deployment model.Deployment,
) error {
	return s.nats.SendPasswordResetEmail(deployment.ID, userID, email, code)
}

func (s *AuthService) SendEmailVerificationEmail(
	userID uint64,
	email string,
	code string,
	deployment model.Deployment,
) error {
	return s.nats.SendVerificationEmail(deployment.ID, userID, email, code)
}

func (s *AuthService) SendSmsOTPVerificationAsync(
	phoneNumber string,
	deployment model.Deployment,
) error {
	// SMS sending would need to be implemented in NATS service
	// For now, we'll skip SMS as the worker only handles email tasks
	return fmt.Errorf("SMS sending not implemented in NATS service")
}

func (s *AuthService) GenerateMagicLink(
	attemptID uint64,
	deployment model.Deployment,
	redirectURI string,
) (string, error) {
	token, err := utils.GenerateSecureToken(32)
	if err != nil {
		return "", err
	}

	key := fmt.Sprintf("magic_link:%d", attemptID)
	if err := s.StoreOTPInCache(key, token); err != nil {
		return "", err
	}

	magicLink := fmt.Sprintf("https://%s/verify-magic-link?token=%s&attempt=%d",
		deployment.FrontendHost, token, attemptID)

	// Add redirect_uri parameter if provided
	if redirectURI != "" {
		magicLink += "&redirect_uri=" + url.QueryEscape(redirectURI)
	}

	return magicLink, nil
}

func (s *AuthService) SendMagicLinkAsync(
	email string,
	magicLink string,
	deployment model.Deployment,
) error {
	// Get user ID for the email
	userEmail, err := s.FindUserByEmail(email)
	if err != nil {
		// For new signups or non-existent users, use 0 as user ID
		return s.nats.SendMagicLinkEmail(deployment.ID, 0, email, magicLink)
	}
	
	return s.nats.SendMagicLinkEmail(deployment.ID, *userEmail.UserID, email, magicLink)
}

func (s *AuthService) VerifyMagicLinkToken(
	attemptID uint64,
	token string,
) error {
	key := fmt.Sprintf("magic_link:%d", attemptID)
	storedToken, err := s.GetOTPFromRedis(key)
	if err != nil {
		return err
	}

	if storedToken != token {
		return errors.New("invalid magic link token")
	}

	s.DeleteOTPFromRedis(key)
	return nil
}

func (s *AuthService) GetRequiredFields(authSettings model.DeploymentAuthSettings) []string {
	var requiredFields []string
	if authSettings.FirstName.Required {
		requiredFields = append(requiredFields, "first_name")
	}
	if authSettings.LastName.Required {
		requiredFields = append(requiredFields, "last_name")
	}
	if authSettings.EmailAddress.Required {
		requiredFields = append(requiredFields, "email_address")
	}
	if authSettings.Username.Required {
		requiredFields = append(requiredFields, "username")
	}
	if authSettings.PhoneNumber.Required {
		requiredFields = append(requiredFields, "phone_number")
	}
	return requiredFields
}

func (s *AuthService) CheckMissingRequiredFields(user *model.User, authSettings model.DeploymentAuthSettings) []string {
	var missingFields []string

	if authSettings.FirstName.Required && user.FirstName == "" {
		missingFields = append(missingFields, "first_name")
	}
	if authSettings.LastName.Required && user.LastName == "" {
		missingFields = append(missingFields, "last_name")
	}
	if authSettings.Username.Required && user.Username == "" {
		missingFields = append(missingFields, "username")
	}
	if authSettings.PhoneNumber.Required && user.PrimaryPhoneNumberID == nil {
		missingFields = append(missingFields, "phone_number")
	}

	return missingFields
}

func (s *AuthService) CheckMissingFieldsFromData(data ProfileCompletionData, authSettings model.DeploymentAuthSettings) []string {
	var missingFields []string

	if authSettings.FirstName.Required && data.FirstName == "" {
		missingFields = append(missingFields, "first_name")
	}
	if authSettings.LastName.Required && data.LastName == "" {
		missingFields = append(missingFields, "last_name")
	}
	if authSettings.EmailAddress.Required && data.Email == "" {
		missingFields = append(missingFields, "email_address")
	}
	if authSettings.Username.Required && data.Username == "" {
		missingFields = append(missingFields, "username")
	}
	if authSettings.PhoneNumber.Required && data.PhoneNumber == "" {
		missingFields = append(missingFields, "phone_number")
	}

	return missingFields
}

func (s *AuthService) ValidateProfileCompletionData(data ProfileCompletionData, requiredFields []string) error {
	for _, field := range requiredFields {
		switch field {
		case "first_name":
			if data.FirstName == "" {
				return handler.ErrRequiredField("First name")
			}
		case "last_name":
			if data.LastName == "" {
				return handler.ErrRequiredField("Last name")
			}
		case "email_address":
			if data.Email == "" {
				return handler.ErrRequiredField("Email address")
			}
		case "username":
			if data.Username == "" {
				return handler.ErrRequiredField("Username")
			}
		case "phone_number":
			if data.PhoneNumber == "" {
				return handler.ErrRequiredField("Phone number")
			}
		}
	}
	return nil
}

func (s *AuthService) ProcessProfileCompletion(
	data ProfileCompletionData,
	authSettings model.DeploymentAuthSettings,
) (bool, []string, []string, error) {
	requiredFields := s.GetRequiredFields(authSettings)

	if err := s.ValidateProfileCompletionData(data, requiredFields); err != nil {
		return false, nil, nil, err
	}

	missingFields := s.CheckMissingFieldsFromData(data, authSettings)
	requiresCompletion := len(missingFields) > 0

	return requiresCompletion, missingFields, requiredFields, nil
}

func (s *AuthService) CreateSignupAttempt(
	b *SignUpRequest,
	hashedPassword string,
	session *model.Session,
	d model.Deployment,
) (*model.SignupAttempt, error) {
	requiredFields := s.GetRequiredFields(d.AuthSettings)

	data := ProfileCompletionData{
		FirstName:   b.FirstName,
		LastName:    b.LastName,
		Username:    b.Username,
		Email:       b.Email,
		PhoneNumber: b.PhoneNumber,
	}

	missingFields := s.CheckMissingFieldsFromData(data, d.AuthSettings)

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

func (s *AuthService) CreateOAuthSignupAttempt(
	email string,
	firstName string,
	lastName string,
	username string,
	provider model.SocialConnectionProvider,
	accessToken string,
	refreshToken string,
	session *model.Session,
	d model.Deployment,
) (*model.SignupAttempt, error) {
	requiredFields := s.GetRequiredFields(d.AuthSettings)

	data := ProfileCompletionData{
		FirstName:   firstName,
		LastName:    lastName,
		Username:    username,
		Email:       email,
		PhoneNumber: "",
	}

	missingFields := s.CheckMissingFieldsFromData(data, d.AuthSettings)

	if d.AuthSettings.PhoneNumber.Required {
		missingFields = append(missingFields, "phone_number")
	}

	var steps []model.SignupAttemptStep
	if d.AuthSettings.VerificationPolicy.Email && email != "" {
		steps = append(steps, model.SignupAttemptStepVerifyEmail)
	}

	attempt := &model.SignupAttempt{
		Model: model.Model{
			ID: snowflake.ID(),
		},
		SessionID:       session.ID,
		FirstName:       firstName,
		LastName:        lastName,
		Email:           email,
		Username:        username,
		PhoneNumber:     "",
		Password:        "",
		RequiredFields:  datatypes.NewJSONSlice(requiredFields),
		MissingFields:   datatypes.NewJSONSlice(missingFields),
		RemainingSteps:  datatypes.NewJSONSlice(steps),
		SSOProvider:     provider,
		SSOAccessToken:  accessToken,
		SSORefreshToken: refreshToken,
		IsOAuthSignup:   true,
	}

	if len(steps) > 0 {
		attempt.CurrentStep = steps[0]
	}

	return attempt, nil
}

func (s *AuthService) CreateOAuthUser(
	attempt *model.SignupAttempt,
	d model.Deployment,
) (*model.User, error) {
	if !attempt.IsOAuthSignup {
		return nil, fmt.Errorf("attempt is not an OAuth signup")
	}

	primaryAddressID := snowflake.ID()

	u := model.User{
		Model: model.Model{
			ID: snowflake.ID(),
		},
		SchemaVersion:         model.SchemaVersionV1,
		FirstName:             attempt.FirstName,
		LastName:              attempt.LastName,
		Username:              attempt.Username,
		SecondFactorPolicy:    d.AuthSettings.SecondFactorPolicy,
		DeploymentID:          d.ID,
		PrimaryEmailAddressID: &primaryAddressID,
		UserEmailAddresses: []model.UserEmailAddress{{
			Model:                model.Model{ID: primaryAddressID},
			EmailAddress:         attempt.Email,
			IsPrimary:            true,
			Verified:             true,
			VerificationStrategy: model.Otp,
			VerifiedAt:           time.Now(),
			DeploymentID:         d.ID,
		}},
		SocialConnections: []model.SocialConnection{{
			Model:              model.Model{ID: snowflake.ID()},
			Provider:           attempt.SSOProvider,
			EmailAddress:       attempt.Email,
			UserEmailAddressID: primaryAddressID,
			AccessToken:        attempt.SSOAccessToken,
			RefreshToken:       attempt.SSORefreshToken,
		}},
	}

	if attempt.PhoneNumber != "" {
		phoneID := snowflake.ID()
		u.UserPhoneNumbers = []model.UserPhoneNumber{{
			Model:        model.Model{ID: phoneID},
			PhoneNumber:  attempt.PhoneNumber,
			Verified:     false,
			DeploymentID: d.ID,
		}}
		if u.PrimaryPhoneNumberID == nil {
			u.PrimaryPhoneNumberID = &phoneID
		}
	}

	return &u, nil
}

const (
	otpExpirationTime = 5 * time.Minute
)

func (s *AuthService) StoreOTPInCache(key string, otp string) error {
	return database.Redis.Set(
		context.Background(),
		fmt.Sprintf("otp:%s", key),
		otp,
		otpExpirationTime,
	).Err()
}

func (s *AuthService) GetOTPFromRedis(key string) (string, error) {
	return database.Redis.Get(
		context.Background(),
		fmt.Sprintf("otp:%s", key),
	).Result()
}

func (s *AuthService) DeleteOTPFromRedis(key string) error {
	return database.Redis.Del(
		context.Background(),
		fmt.Sprintf("otp:%s", key),
	).Err()
}

func (s *AuthService) Store2FAMethodInCache(key string, method string) error {
	return database.Redis.Set(
		context.Background(),
		fmt.Sprintf("2fa:%s", key),
		method,
		otpExpirationTime,
	).Err()
}

func (s *AuthService) Get2FAMethodFromCache(key string) (string, error) {
	return database.Redis.Get(
		context.Background(),
		fmt.Sprintf("2fa:%s", key),
	).Result()
}

func (s *AuthService) Delete2FAMethodFromCache(key string) error {
	return database.Redis.Del(
		context.Background(),
		fmt.Sprintf("2fa:%s", key),
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

	ipLocation := s.getIPLocation(ip)

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

func (s *AuthService) getIPLocation(ip string) IPLocation {
	defaultLocation := IPLocation{
		Status:      "fail",
		Country:     "Unknown",
		CountryCode: "XX",
		City:        "Unknown",
		RegionName:  "Unknown",
		Region:      "Unknown",
	}

	if ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.") {
		return defaultLocation
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(
		"http://ip-api.com/json/" + ip + "?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query",
	)
	if err != nil {
		return s.getIPLocationFallback(ip, client)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return s.getIPLocationFallback(ip, client)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return s.getIPLocationFallback(ip, client)
	}

	var ipLocation IPLocation
	err = json.Unmarshal(body, &ipLocation)
	if err != nil {
		return s.getIPLocationFallback(ip, client)
	}

	if ipLocation.Status != "success" {
		return s.getIPLocationFallback(ip, client)
	}

	return ipLocation
}

func (s *AuthService) getIPLocationFallback(ip string, client *http.Client) IPLocation {
	defaultLocation := IPLocation{
		Status:      "fail",
		Country:     "Unknown",
		CountryCode: "XX",
		City:        "Unknown",
		RegionName:  "Unknown",
		Region:      "Unknown",
	}

	resp, err := client.Get("https://ipapi.co/" + ip + "/json/")
	if err != nil {
		return defaultLocation
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return defaultLocation
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return defaultLocation
	}

	var fallbackResponse struct {
		IP          string  `json:"ip"`
		City        string  `json:"city"`
		Region      string  `json:"region"`
		RegionCode  string  `json:"region_code"`
		Country     string  `json:"country_name"`
		CountryCode string  `json:"country_code"`
		Continent   string  `json:"continent_code"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
		Timezone    string  `json:"timezone"`
		Error       bool    `json:"error"`
	}

	err = json.Unmarshal(body, &fallbackResponse)
	if err != nil || fallbackResponse.Error {
		return defaultLocation
	}

	return IPLocation{
		Status:        "success",
		Country:       fallbackResponse.Country,
		CountryCode:   fallbackResponse.CountryCode,
		Region:        fallbackResponse.RegionCode,
		RegionName:    fallbackResponse.Region,
		City:          fallbackResponse.City,
		ContinentCode: fallbackResponse.Continent,
		Lat:           fallbackResponse.Latitude,
		Long:          fallbackResponse.Longitude,
		Timezone:      fallbackResponse.Timezone,
	}
}

func (s *AuthService) ValidateEmailRestrictions(email string, restrictions model.DeploymentRestrictions) error {
	if restrictions.AllowlistEnabled && len(restrictions.AllowlistedResources) > 0 {
		allowed := false
		emailDomain := strings.Split(email, "@")[1]
		for _, allowedResource := range restrictions.AllowlistedResources {
			if email == allowedResource || emailDomain == allowedResource {
				allowed = true
				break
			}
		}
		if !allowed {
			return handler.ErrEmailNotAllowed
		}
	}

	if restrictions.BlocklistEnabled && len(restrictions.BlocklistedResources) > 0 {
		emailDomain := strings.Split(email, "@")[1]
		for _, blockedResource := range restrictions.BlocklistedResources {
			if email == blockedResource || emailDomain == blockedResource {
				return handler.ErrEmailBlocked
			}
		}
	}

	if restrictions.BlockDisposableEmails {
		if s.isDisposableEmail(email) {
			return handler.ErrDisposableEmail
		}
	}

	if err := s.validateEmailMXRecord(email); err != nil {
		return handler.ErrEmailNotAllowed
	}

	return nil
}

func (s *AuthService) ValidatePhoneRestrictions(phoneNumber string, restrictions model.DeploymentRestrictions) error {
	telesignService := service.NewTelesignService(
		config.GetEnv("TELESIGN_CUSTOMER_ID", ""),
		config.GetEnv("TELESIGN_API_KEY", ""),
	)

	if telesignService.CustomerID != "" && telesignService.APIKey != "" {
		result, err := telesignService.ValidatePhoneNumber(phoneNumber)
		if err != nil {
			return s.validatePhoneBasic(phoneNumber, restrictions)
		}

		if !result.IsValid {
			return handler.ErrVoipNumberBlocked
		}

		if result.IsBlocked {
			return handler.ErrVoipNumberBlocked
		}

		if restrictions.BlockVoipNumbers && result.IsVOIP {
			return handler.ErrVoipNumberBlocked
		}

		if restrictions.BlockVoipNumbers && result.IsHighRisk {
			return handler.ErrVoipNumberBlocked
		}

		if restrictions.CountryRestrictions.Enabled && len(restrictions.CountryRestrictions.CountryCodes) > 0 {
			allowed := false
			for _, allowedCountry := range restrictions.CountryRestrictions.CountryCodes {
				if result.CountryCode == allowedCountry {
					allowed = true
					break
				}
			}
			if !allowed {
				return handler.ErrCountryRestricted
			}
		}
	} else {
		return s.validatePhoneBasic(phoneNumber, restrictions)
	}

	return nil
}

func (s *AuthService) validatePhoneBasic(phoneNumber string, restrictions model.DeploymentRestrictions) error {
	if restrictions.CountryRestrictions.Enabled && len(restrictions.CountryRestrictions.CountryCodes) > 0 {
		countryCode := s.extractCountryCodeFromPhone(phoneNumber)
		allowed := false
		for _, allowedCountry := range restrictions.CountryRestrictions.CountryCodes {
			if countryCode == allowedCountry {
				allowed = true
				break
			}
		}
		if !allowed {
			return handler.ErrCountryRestricted
		}
	}

	return nil
}

func (s *AuthService) ValidateBannedKeywords(b *SignUpRequest, restrictions model.DeploymentRestrictions) error {
	if len(restrictions.BannedKeywords) == 0 {
		return nil
	}

	textToCheck := strings.ToLower(strings.Join([]string{
		b.FirstName,
		b.LastName,
		b.Username,
		b.Email,
	}, " "))

	for _, keyword := range restrictions.BannedKeywords {
		if strings.Contains(textToCheck, strings.ToLower(keyword)) {
			return handler.ErrBannedKeyword
		}
	}

	return nil
}

func (s *AuthService) ValidateIPCountryRestrictions(ctx *fiber.Ctx, restrictions model.DeploymentRestrictions) error {
	if !restrictions.CountryRestrictions.Enabled || len(restrictions.CountryRestrictions.CountryCodes) == 0 {
		return nil
	}

	var ip string
	if len(ctx.IPs()) > 0 {
		ip = ctx.IPs()[0]
	} else {
		ip = ctx.IP()
	}

	ipLocation := s.getIPLocation(ip)

	if ipLocation.Status != "success" || ipLocation.CountryCode == "" || ipLocation.CountryCode == "XX" {
		return nil
	}

	allowed := false
	for _, allowedCountry := range restrictions.CountryRestrictions.CountryCodes {
		if ipLocation.CountryCode == allowedCountry {
			allowed = true
			break
		}
	}

	if !allowed {
		return handler.ErrCountryRestricted
	}

	return nil
}

func (s *AuthService) isDisposableEmail(email string) bool {
	domain := strings.ToLower(strings.Split(email, "@")[1])

	disposableDomains := []string{
		"10minutemail.com", "10minutemail.net", "10minutemail.org", "guerrillamail.com",
		"guerrillamail.net", "guerrillamail.org", "guerrillamail.biz", "guerrillamail.de",
		"mailinator.com", "mailinator.net", "mailinator.org", "tempmail.org", "temp-mail.org",
		"throwaway.email", "yopmail.com", "yopmail.fr", "yopmail.net", "maildrop.cc",
		"sharklasers.com", "grr.la", "guerrillamailblock.com", "pokemail.net", "spam4.me",
		"bccto.me", "chacuo.net", "dispostable.com", "fakeinbox.com", "filzmail.com",
		"get-mail.tk", "getairmail.com", "getnada.com", "harakirimail.com", "inboxkitten.com",
		"koszmail.pl", "kurzepost.de", "lroid.com", "mohmal.com", "mytemp.email",
		"nada.email", "temp.email", "tempail.com", "tempemail.net", "tempinbox.com",
		"tempr.email", "trashmail.com", "wegwerfmail.de", "zehnminutenmail.de",
		"0-mail.com", "0815.ru", "0clickemail.com", "0wnd.net", "0wnd.org", "10mail.org",
		"20email.eu", "20mail.it", "20minutemail.com", "2prong.com", "30minutemail.com",
		"33mail.com", "3d-painting.com", "4warding.com", "4warding.net", "4warding.org",
		"60minutemail.com", "675hosting.com", "675hosting.net", "675hosting.org", "6url.com",
		"75hosting.com", "75hosting.net", "75hosting.org", "7tags.com", "9ox.net",
		"a-bc.net", "a45.in", "abyssmail.com", "ac20mail.in", "acentri.com", "advantimo.com",
		"afrobacon.com", "ajaxapp.net", "ama-trade.de", "ama-trans.de", "amiri.net",
		"amiriindustrial.com", "anonbox.net", "anonmails.de", "anonymbox.com", "antichef.com",
		"antichef.net", "antireg.ru", "antispam.de", "antispammail.de", "armyspy.com",
		"artman-conception.com", "azmeil.tk", "baxomale.ht.cx", "beefmilk.com", "bigstring.com",
		"binkmail.com", "bio-muesli.net", "bobmail.info", "bodhi.lawlita.com", "bofthew.com",
		"bootybay.de", "boun.cr", "bouncr.com", "boxformail.in", "br.mintemail.com",
		"breakthru.com", "brefmail.com", "brennendesreich.de", "broadbandninja.com",
		"bsnow.net", "bspamfree.org", "bugmenot.com", "bumpymail.com", "burnthespam.info",
		"burstmail.info", "buymoreplays.com", "byom.de", "c2.hu", "card.zp.ua",
		"casualdx.com", "cek.pm", "centermail.com", "centermail.net", "chammy.info",
		"childsavetrust.org", "chogmail.com", "choicemail1.com", "clixser.com", "cmail.net",
		"cmail.org", "coldemail.info", "cool.fr.nf", "correo.blogos.net", "cosmorph.com",
		"courriel.fr.nf", "courrieltemporaire.com", "crapmail.org", "crazymailing.com",
		"cubiclink.com", "curryworld.de", "cust.in", "cuvox.de", "d3p.dk", "dacoolest.com",
		"dandikmail.com", "dayrep.com", "dcemail.com", "deadaddress.com", "deadspam.com",
		"delikkt.de", "despam.it", "despammed.com", "devnullmail.com", "dfgh.net",
		"digitalsanctuary.com", "dingbone.com", "disposableaddress.com", "disposableemailaddresses.com",
		"disposableinbox.com", "dispose.it", "dispostable.com", "dm.w3internet.com",
		"dodgeit.com", "dodgit.com", "dodgit.org", "donemail.ru", "dontreg.com",
		"dontsendmespam.de", "drdrb.net", "dump-email.info", "dumpandjunk.com", "dumpmail.de",
		"dumpyemail.com", "e-mail.com", "e-mail.org", "e4ward.com", "easytrashmail.com",
		"einrot.com", "einrot.de", "email60.com", "emaildienst.de", "emailgo.de",
		"emailias.com", "emailinfive.com", "emailmiser.com", "emailsensei.com", "emailtemporanea.com",
		"emailtemporanea.net", "emailtemporar.ro", "emailtemporario.com.br", "emailthe.net",
		"emailtmp.com", "emailto.de", "emailwarden.com", "emailx.at.hm", "emailxfer.com",
		"emeil.in", "emeil.ir", "emz.net", "enterto.com", "ephemail.net", "etranquil.com",
		"etranquil.net", "etranquil.org", "evopo.com", "explodemail.com", "express.net.ua",
		"eyepaste.com", "facebook-email.cf", "facebook-email.ga", "facebook-email.ml",
		"fakedemail.com", "fakeinformation.com", "fakemail.fr", "fakemailz.com", "fammix.com",
		"fansworldwide.de", "fantasymail.de", "fastacura.com", "fastchevy.com", "fastchrysler.com",
		"fastkawasaki.com", "fastmazda.com", "fastmitsubishi.com", "fastnissan.com", "fastsubaru.com",
		"fastsuzuki.com", "fasttoyota.com", "fastyamaha.com", "fatflap.com", "fdfdsfds.com",
		"fightallspam.com", "fiifke.de", "filzmail.com", "fixmail.tk", "fizmail.com",
		"fleckens.hu", "flyspam.com", "footard.com", "forgetmail.com", "fr33mail.info",
		"frapmail.com", "freegmail.net", "freemails.cf", "freemails.ga", "freemails.ml",
		"freundin.ru", "friendlymail.co.uk", "front14.org", "fuckingduh.com", "fudgerub.com",
		"fux0ringduh.com", "garliclife.com", "gelitik.in", "get1mail.com", "get2mail.fr",
		"getonemail.com", "getonemail.net", "ghosttexter.de", "girlsundertheinfluence.com",
		"gishpuppy.com", "gmial.com", "goemailgo.com", "gotmail.net", "gotmail.org",
		"gotti.otherinbox.com", "great-host.in", "greensloth.com", "grr.la", "gsrv.co.uk",
		"guerillamail.biz", "guerillamail.com", "guerillamail.de", "guerillamail.net",
		"guerillamail.org", "guerrillamailblock.com", "h.mintemail.com", "h8s.org",
		"hacccc.com", "haltospam.com", "harakirimail.com", "hatespam.org", "herp.in",
		"hidemail.de", "hidzz.com", "hmamail.com", "hopemail.biz", "hotpop.com",
		"hulapla.de", "ieatspam.eu", "ieatspam.info", "ieh-mail.de", "ikbenspamvrij.nl",
		"imails.info", "inbax.tk", "inbox.si", "inboxalias.com", "inboxclean.com",
		"inboxclean.org", "inboxproxy.com", "incognitomail.com", "incognitomail.net",
		"incognitomail.org", "insorg-mail.info", "instant-mail.de", "instantemailaddress.com",
		"ipoo.org", "irish2me.com", "iwi.net", "jetable.com", "jetable.fr.nf",
		"jetable.net", "jetable.org", "jnxjn.com", "jourrapide.com", "jsrsolutions.com",
		"junk1e.com", "junkmail.ga", "junkmail.gq", "kasmail.com", "kaspop.com",
		"keepmymail.com", "killmail.com", "killmail.net", "kir.ch.tc", "klassmaster.com",
		"klzlk.com", "kook.ml", "koszmail.pl", "kurzepost.de", "l33r.eu",
		"lackmail.net", "lags.us", "landmail.co", "lastmail.co", "lavabit.com",
		"lawlita.com", "letthemeatspam.com", "lhsdv.com", "lifebyfood.com", "link2mail.net",
		"litedrop.com", "lol.ovpn.to", "lolfreak.net", "lookugly.com", "lopl.co.cc",
		"lortemail.dk", "lr78.com", "lroid.com", "lukop.dk", "m4ilweb.info",
		"maboard.com", "mail-filter.com", "mail-temporaire.fr", "mail.by", "mail.mezimages.net",
		"mail.zp.ua", "mail1a.de", "mail21.cc", "mail2rss.org", "mail333.com",
		"mail4trash.com", "mailbidon.com", "mailbiz.biz", "mailblocks.com", "mailbucket.org",
		"mailcatch.com", "mailde.de", "mailde.info", "maildrop.cc", "maildrop.cf",
		"maildrop.ga", "maildrop.gq", "maildrop.ml", "maileater.com", "mailed.ro",
		"mailexpire.com", "mailfa.tk", "mailforspam.com", "mailfreeonline.com", "mailguard.me",
		"mailin8r.com", "mailinater.com", "mailinator.com", "mailinator.net", "mailinator.org",
		"mailinator2.com", "mailincubator.com", "mailismagic.com", "mailme.lv", "mailme24.com",
		"mailmetrash.com", "mailmoat.com", "mailnator.com", "mailnesia.com", "mailnull.com",
		"mailorg.org", "mailpick.biz", "mailrock.biz", "mailscrap.com", "mailshell.com",
		"mailsiphon.com", "mailtemp.info", "mailtome.de", "mailtothis.com", "mailtrash.net",
		"mailtv.net", "mailtv.tv", "mailzilla.com", "mailzilla.org", "makemetheking.com",
		"manybrain.com", "mbx.cc", "mciek.com", "mega.zik.dj", "meinspamschutz.de",
		"meltmail.com", "messagebeamer.de", "mezimages.net", "mierdamail.com", "migmail.pl",
		"mintemail.com", "mjukglass.nu", "mobi.web.id", "moburl.com", "mohmal.com",
		"moncourrier.fr.nf", "monemail.fr.nf", "monmail.fr.nf", "monumentmail.com", "mt2009.com",
		"mt2014.com", "mycard.net.ua", "mycleaninbox.net", "myemailboxy.com", "mymail-in.net",
		"mymailoasis.com", "mynetstore.de", "mypacks.net", "mypartyclip.de", "myphantomemail.com",
		"myspaceinc.com", "myspaceinc.net", "myspaceinc.org", "myspacepimpedup.com", "myspamless.com",
		"mytemp.email", "mytempemail.com", "mytempmail.com", "mytrashmail.com", "nabuma.com",
		"neomailbox.com", "nepwk.com", "nervmich.net", "nervtmich.net", "netmails.com",
		"netmails.net", "netzidiot.de", "neverbox.com", "nice-4u.com", "nincsmail.com",
		"nincsmail.hu", "nnh.com", "no-spam.ws", "noblepioneer.com", "nobugmail.com",
		"noclickemail.com", "nogmailspam.info", "nomail.xl.cx", "nomail2me.com", "nomorespamemails.com",
		"nonspam.eu", "nonspammer.de", "noref.in", "nospam.ze.tc", "nospam4.us",
		"nospamfor.us", "nospammail.net", "nospamthanks.info", "notmailinator.com", "notsharingmy.info",
		"nowhere.org", "nowmymail.com", "nurfuerspam.de", "nus.edu.sg", "nwldx.com",
		"objectmail.com", "obobbo.com", "odnorazovoe.ru", "one-time.email", "oneoffemail.com",
		"onewaymail.com", "onlatedotcom.info", "online.ms", "opayq.com", "ordinaryamerican.net",
		"otherinbox.com", "ovpn.to", "owlpic.com", "pancakemail.com", "paplease.com",
		"pcusers.otherinbox.com", "pjkd.com", "plexolan.de", "poczta.onet.pl", "politikerclub.de",
		"poofy.org", "pookmail.com", "privacy.net", "privatdemail.net", "proxymail.eu",
		"prtnx.com", "putthisinyourspamdatabase.com", "pwrby.com", "quickinbox.com", "rcpt.at",
		"reallymymail.com", "realtyalerts.ca", "receiveee.com", "recode.me", "recursor.net",
		"recyclebin.jp", "regbypass.com", "regbypass.comsafe-mail.net", "rejectmail.com", "reliable-mail.com",
		"rhyta.com", "rklips.com", "rmqkr.net", "royal.net", "rppkn.com",
		"rtrtr.com", "s0ny.net", "safe-mail.net", "safersignup.de", "safetymail.info",
		"safetypost.de", "sandelf.de", "saynotospams.com", "schafmail.de", "schrott-email.de",
		"secretemail.de", "secure-mail.biz", "selfdestructingmail.com", "selfdestructingmail.org", "sendspamhere.de",
		"sharklasers.com", "shieldedmail.com", "shieldemail.com", "shiftmail.com", "shitmail.me",
		"shitware.nl", "shmeriously.com", "shortmail.net", "sibmail.com", "sinnlos-mail.de",
		"siteposter.net", "skeefmail.com", "slaskpost.se", "slopsbox.com", "slushmail.com",
		"smashmail.de", "smellfear.com", "snakemail.com", "sneakemail.com", "snkmail.com",
		"sofimail.com", "sofort-mail.de", "sogetthis.com", "soodonims.com", "spam.la",
		"spam.su", "spam4.me", "spamail.de", "spambob.com", "spambob.net",
		"spambob.org", "spambog.com", "spambog.de", "spambog.ru", "spambox.info",
		"spambox.irishspringtours.com", "spambox.us", "spamcannon.com", "spamcannon.net", "spamcon.org",
		"spamcorptastic.com", "spamcowboy.com", "spamcowboy.net", "spamcowboy.org", "spamday.com",
		"spamex.com", "spamfree24.com", "spamfree24.de", "spamfree24.eu", "spamfree24.net",
		"spamfree24.org", "spamgoes.com", "spamgourmet.com", "spamgourmet.net", "spamgourmet.org",
		"spamherelots.com", "spamhereplease.com", "spamhole.com", "spami.spam.co.za", "spaminator.de",
		"spamkill.info", "spaml.com", "spaml.de", "spammotel.com", "spamobox.com",
		"spamoff.de", "spamslicer.com", "spamspot.com", "spamthis.co.uk", "spamthisplease.com",
		"spamtrail.com", "spamtroll.net", "speed.1s.fr", "spoofmail.de", "stuffmail.de",
		"super-auswahl.de", "supergreatmail.com", "supermailer.jp", "superrito.com", "superstachel.de",
		"suremail.info", "talkinator.com", "tapchicuoihoi.com", "teewars.org", "teleworm.com",
		"teleworm.us", "temp-mail.org", "temp-mail.ru", "temp.emeraldwebmail.com", "tempail.com",
		"tempalias.com", "tempe-mail.com", "tempemail.biz", "tempemail.com", "tempinbox.co.uk",
		"tempinbox.com", "tempmail.eu", "tempmail2.com", "tempmaildemo.com", "tempmailer.com",
		"tempmailer.de", "tempomail.fr", "temporarily.de", "temporarioemail.com.br", "temporaryemail.net",
		"temporaryforwarding.com", "temporaryinbox.com", "temporarymailaddress.com", "tempthe.net", "tempymail.com",
		"thanksnospam.info", "thankyou2010.com", "thc.st", "thelimestones.com", "thisisnotmyrealemail.com",
		"thismail.net", "throwawayemailaddresses.com", "tilien.com", "tittbit.in", "tizi.com",
		"tmail.ws", "tmailinator.com", "toiea.com", "toomail.biz", "topranklist.de",
		"tradermail.info", "trash-amil.com", "trash-mail.at", "trash-mail.com", "trash-mail.de",
		"trash2009.com", "trashdevil.com", "trashdevil.de", "trashemail.de", "trashmail.at",
		"trashmail.com", "trashmail.de", "trashmail.me", "trashmail.net", "trashmail.org",
		"trashmail.ws", "trashmailer.com", "trashymail.com", "trashymail.net", "trbvm.com",
		"trialmail.de", "trillianpro.com", "tryalert.com", "turual.com", "twinmail.de",
		"tyldd.com", "uggsrock.com", "umail.net", "upliftnow.com", "uplipht.com",
		"uroid.com", "us.af", "venompen.com", "veryrealemail.com", "viditag.com",
		"viewcastmedia.com", "viewcastmedia.net", "viewcastmedia.org", "vomoto.com", "vubby.com",
		"walala.org", "walkmail.net", "webemail.me", "webm4il.info", "webuser.in",
		"wh4f.org", "whopy.com", "willselfdestruct.com", "winemaven.info", "wronghead.com",
		"wuzup.net", "wuzupmail.net", "www.e4ward.com", "www.gishpuppy.com", "www.mailinator.com",
		"wwwnew.eu", "x.ip6.li", "xagloo.com", "xemaps.com", "xents.com",
		"xmaily.com", "xoxy.net", "yapped.net", "yeah.net", "yep.it",
		"yogamaven.com", "yopmail.com", "yopmail.fr", "yopmail.net", "yourdomain.com",
		"ypmail.webredirect.org", "yuurok.com", "z1p.biz", "za.com", "zehnminutenmail.de",
		"zetmail.com", "zippymail.info", "zoaxe.com", "zoemail.org", "zomg.info",
	}

	for _, disposableDomain := range disposableDomains {
		if domain == disposableDomain {
			return true
		}
	}

	disposablePatterns := []string{
		"temp", "disposable", "throw", "trash", "fake", "spam", "guerrilla", "mailinator",
		"10min", "minute", "tempor", "jetable", "wegwerf", "kurz", "nada", "guerilla",
	}

	for _, pattern := range disposablePatterns {
		if strings.Contains(domain, pattern) {
			return true
		}
	}

	return false
}

func (s *AuthService) validateEmailMXRecord(email string) error {
	domain := strings.Split(email, "@")[1]

	mxRecords, err := net.LookupMX(domain)
	if err != nil || len(mxRecords) == 0 {
		_, err := net.LookupHost(domain)
		if err != nil {
			return fmt.Errorf("invalid email domain: %s", domain)
		}
	}

	return nil
}

func (s *AuthService) DetermineVerificationStepsForProfileCompletion(
	data ProfileCompletionData,
	userID *uint64,
	authSettings model.DeploymentAuthSettings,
) []string {
	var steps []string

	// Check if email verification is needed
	if data.Email != "" && authSettings.VerificationPolicy.Email {
		needsEmailVerification := true

		// If this is for an existing user (signin completion), check if email is already verified
		if userID != nil {
			var existingEmail model.UserEmailAddress
			err := s.db.Where("user_id = ? AND email_address = ? AND verified = true",
				*userID, data.Email).First(&existingEmail).Error
			needsEmailVerification = err != nil // If no verified email found, verification is needed
		}

		if needsEmailVerification {
			steps = append(steps, "verify_email")
		}
	}

	// Check if phone verification is needed
	if data.PhoneNumber != "" && authSettings.VerificationPolicy.PhoneNumber {
		needsPhoneVerification := true

		// If this is for an existing user (signin completion), check if phone is already verified
		if userID != nil {
			var existingPhone model.UserPhoneNumber
			err := s.db.Where("user_id = ? AND phone_number = ? AND verified = true",
				*userID, data.PhoneNumber).First(&existingPhone).Error
			needsPhoneVerification = err != nil // If no verified phone found, verification is needed
		}

		if needsPhoneVerification {
			steps = append(steps, "verify_phone")
		}
	}

	return steps
}

func (s *AuthService) extractCountryCodeFromPhone(phoneNumber string) string {
	digits := regexp.MustCompile(`\D`).ReplaceAllString(phoneNumber, "")

	if strings.HasPrefix(phoneNumber, "+") {
		if len(digits) >= 2 {
			oneDigitCodes := []string{"1", "7"}
			for _, code := range oneDigitCodes {
				if strings.HasPrefix(digits, code) {
					return code
				}
			}

			if len(digits) >= 2 {
				twoDigitCode := digits[:2]
				commonTwoDigit := []string{
					"20", "27", "30", "31", "32", "33", "34", "36", "39", "40",
					"41", "43", "44", "45", "46", "47", "48", "49", "51", "52",
					"53", "54", "55", "56", "57", "58", "60", "61", "62", "63",
					"64", "65", "66", "81", "82", "84", "86", "90", "91", "92",
					"93", "94", "95", "98",
				}
				for _, code := range commonTwoDigit {
					if twoDigitCode == code {
						return code
					}
				}
			}

			if len(digits) >= 3 {
				threeDigitCode := digits[:3]
				commonThreeDigit := []string{
					"212", "213", "216", "218", "220", "221", "222", "223", "224",
					"225", "226", "227", "228", "229", "230", "231", "232", "233",
					"234", "235", "236", "237", "238", "239", "240", "241", "242",
					"243", "244", "245", "246", "247", "248", "249", "250", "251",
					"252", "253", "254", "255", "256", "257", "258", "260", "261",
					"262", "263", "264", "265", "266", "267", "268", "269", "290",
					"291", "297", "298", "299", "350", "351", "352", "353", "354",
					"355", "356", "357", "358", "359", "370", "371", "372", "373",
					"374", "375", "376", "377", "378", "380", "381", "382", "383",
					"385", "386", "387", "389", "420", "421", "423", "500", "501",
					"502", "503", "504", "505", "506", "507", "508", "509", "590",
					"591", "592", "593", "594", "595", "596", "597", "598", "599",
					"670", "672", "673", "674", "675", "676", "677", "678", "679",
					"680", "681", "682", "683", "684", "685", "686", "687", "688",
					"689", "690", "691", "692", "850", "852", "853", "855", "856",
					"880", "886", "960", "961", "962", "963", "964", "965", "966",
					"967", "968", "970", "971", "972", "973", "974", "975", "976",
					"977", "992", "993", "994", "995", "996", "998",
				}
				for _, code := range commonThreeDigit {
					if threeDigitCode == code {
						return code
					}
				}
			}
		}
	}

	return "1"
}

func (s *AuthService) GetAvailable2FAMethods(userID uint64) []string {
	var methods []string

	var phoneCount int64
	s.db.Model(&model.UserPhoneNumber{}).
		Where("user_id = ? AND verified = true", userID).
		Count(&phoneCount)
	if phoneCount > 0 {
		methods = append(methods, "phone_otp")
	}

	var authenticatorCount int64
	s.db.Model(&model.UserAuthenticator{}).
		Where("user_id = ? AND verified = true", userID).
		Count(&authenticatorCount)
	if authenticatorCount > 0 {
		methods = append(methods, "authenticator")
	}

	var user model.User
	if err := s.db.Select("backup_codes").Where("id = ?", userID).First(&user).Error; err == nil {
		if len(user.BackupCodes) > 0 {
			methods = append(methods, "backup_code")
		}
	}

	return methods
}
