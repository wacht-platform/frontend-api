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
	"strconv"
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
		panic(fmt.Sprintf("Failed to initialize NATS service: %v", err))
	}

	return &AuthService{
		db:   database.Connection,
		nats: natsService,
	}
}

func (s *AuthService) FindUserByEmail(
	email string,
	deploymentID uint64,
) (*model.UserEmailAddress, error) {
	var userEmail model.UserEmailAddress
	if res := s.db.Where(&model.UserEmailAddress{EmailAddress: email, DeploymentID: deploymentID}).Joins("User").First(&userEmail); res.RowsAffected == 0 {
		return nil, handler.ErrUserNotFound
	} else if res.Error != nil {
		return nil, res.Error
	}

	return &userEmail, nil
}

func (s *AuthService) FindUserByVerifiedEmail(
	email string,
	deploymentID uint64,
) (*model.UserEmailAddress, error) {
	var userEmail model.UserEmailAddress
	if res := s.db.Where(&model.UserEmailAddress{EmailAddress: email, Verified: true, DeploymentID: deploymentID}).Joins("User").First(&userEmail); res.RowsAffected == 0 {
		return nil, handler.ErrUserNotFound
	} else if res.Error != nil {
		return nil, res.Error
	}

	return &userEmail, nil
}

func (s *AuthService) FindUserByEmailID(
	emailId uint64, deploymentID uint64,
) (*model.UserEmailAddress, error) {
	var userEmail model.UserEmailAddress
	if res := s.db.Where(&model.UserEmailAddress{Model: model.Model{ID: emailId}, DeploymentID: deploymentID}).Joins("User").First(&userEmail); res.RowsAffected == 0 {
		return nil, handler.ErrUserNotFound
	} else if res.Error != nil {
		return nil, res.Error
	}
	return &userEmail, nil
}

func (s *AuthService) FindUserByPhoneNumber(
	phoneNumber string,
	countryCode string,
	deploymentID uint64,
) (*model.UserPhoneNumber, error) {
	var userPhone model.UserPhoneNumber
	if res := s.db.Where(&model.UserPhoneNumber{
		PhoneNumber:  phoneNumber,
		CountryCode:  countryCode,
		Verified:     true,
		DeploymentID: deploymentID,
	}).Joins("User").First(&userPhone); res.RowsAffected == 0 {
		return nil, handler.ErrUserNotFound
	} else if res.Error != nil {
		return nil, res.Error
	}

	return &userPhone, nil
}

func (s *AuthService) FindUserByPhoneNumberID(
	phoneId uint64,
	deploymentID uint64,
) (*model.UserPhoneNumber, error) {
	var userPhone model.UserPhoneNumber
	if res := s.db.Where(&model.UserPhoneNumber{Model: model.Model{ID: phoneId}, DeploymentID: deploymentID}).
		Joins("User").
		Preload("User.UserEmailAddresses").
		First(&userPhone); res.RowsAffected == 0 {
		return nil, handler.ErrUserNotFound
	} else if res.Error != nil {
		return nil, res.Error
	}
	return &userPhone, nil
}

func (s *AuthService) FindUserByUsername(
	username string,
	deploymentID uint64,
) (*model.User, error) {
	var user model.User
	if res := s.db.Where(&model.User{Username: username, DeploymentID: deploymentID}).First(&user); res.RowsAffected == 0 {
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

func (s *AuthService) MaskPhoneNumber(countryCode, phoneNumber string) string {
	if len(phoneNumber) < 4 {
		return phoneNumber
	}
	masked := countryCode + strings.Repeat("*", len(phoneNumber)-4) + phoneNumber[len(phoneNumber)-4:]
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
	deployment *model.Deployment,
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
	attempt.FirstMethodAuthenticated = completed

	if slices.Contains(steps, model.SignInAttemptStepVerifySecondFactor) {
		attempt.SecondMethodAuthenticationRequired = true
		if userID != nil {
			attempt.Available2FAMethods = datatypes.NewJSONSlice(s.GetAvailable2FAMethods(*userID, deployment))
		}
	}

	return attempt
}

func (s *AuthService) ValidateSignUpRequest(
	b *SignUpRequest,
	d model.Deployment,
) error {
	if d.AuthSettings.FirstName.Enabled && d.AuthSettings.FirstName.Required && b.FirstName == "" {
		return handler.ErrRequiredField("First name")
	}
	if d.AuthSettings.LastName.Enabled && d.AuthSettings.LastName.Required && b.LastName == "" {
		return handler.ErrRequiredField("Last name")
	}
	if d.AuthSettings.EmailAddress.Enabled && d.AuthSettings.EmailAddress.Required && b.Email == "" {
		return handler.ErrRequiredField("Email address")
	}
	if d.AuthSettings.Username.Enabled && d.AuthSettings.Username.Required && b.Username == "" {
		return handler.ErrRequiredField("Username")
	}
	if d.AuthSettings.PhoneNumber.Enabled && d.AuthSettings.PhoneNumber.Required && b.PhoneNumber == "" {
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
				Model:        model.Model{ID: phoneNumberID},
				PhoneNumber:  b.PhoneNumber,
				CountryCode:  b.PhoneCountryCode,
				Verified:     false,
				DeploymentID: deploymentID,
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
	deployment *model.Deployment,
	session *model.Session,
	ctx *fiber.Ctx,
) (*model.Signin, error) {
	deploymentSettings := deployment.AuthSettings
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

	missingFields := s.CheckMissingRequiredFields(&email.User, deploymentSettings)
	requiresCompletion := len(missingFields) > 0
	secondFactorEnforced := email.User.SecondFactorPolicy == model.SecondFactorPolicyEnforced

	var steps []model.SignInAttemptStep
	if secondFactorEnforced {
		steps = append(steps, model.SignInAttemptStepVerifySecondFactor)
	}
	if requiresCompletion {
		steps = append(steps, model.SignInAttemptStepCompleteProfile)
	}

	attempt.UserID = &email.User.ID
	attempt.IdentifierID = &email.ID
	attempt.FirstMethodAuthenticated = true // OAuth is already authenticated

	if len(steps) > 0 {
		// Has remaining steps
		attempt.RemainingSteps = datatypes.NewJSONSlice(steps)
		attempt.CurrentStep = steps[0]

		if secondFactorEnforced {
			attempt.SecondMethodAuthenticationRequired = true
		}

		if requiresCompletion {
			attempt.RequiresCompletion = true
			attempt.MissingFields = datatypes.NewJSONSlice(missingFields)
			requiredFields := s.GetRequiredFields(deploymentSettings)
			attempt.RequiredFields = datatypes.NewJSONSlice(requiredFields)
		}
		attempt.Available2FAMethods = datatypes.NewJSONSlice(s.GetAvailable2FAMethods(email.User.ID, deployment))
		return nil, nil
	}

	for _, signin := range session.Signins {
		if *signin.UserID == email.User.ID {
			return &signin, nil
		}
	}

	signIn := s.CreateSignin(email.User.ID, attempt.SessionID, ctx, deploymentSettings.SessionValidityPeriod)
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

func (s *AuthService) CheckEmailExists(email string, deploymentID uint64) bool {
	var count int64
	s.db.Model(&model.UserEmailAddress{}).
		Where("email_address = ? AND deployment_id = ?", email, deploymentID).
		Count(&count)
	return count > 0
}

func (s *AuthService) CheckUsernameExists(username string, deploymentID uint64) bool {
	var count int64
	s.db.Model(&model.User{}).
		Where("username = ? AND deployment_id = ?", username, deploymentID).
		Count(&count)
	return count > 0
}

func (s *AuthService) CheckUserphoneExists(phone string, countryCode string, deploymentID uint64) bool {
	var count int64
	s.db.Model(&model.UserPhoneNumber{}).
		Where("phone_number = ? AND country_code = ? AND deployment_id = ?", phone, countryCode, deploymentID).
		Count(&count)
	return count > 0
}

func (s *AuthService) CheckIdentifierAvailability(
	identifier string,
	identifierType string,
	deploymentID uint64,
) (bool, error) {
	switch identifierType {
	case "email":
		return s.CheckEmailExists(identifier, deploymentID), nil
	case "username":
		return s.CheckUsernameExists(identifier, deploymentID), nil
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
	// Basic validation with minimal requirements for backwards compatibility
	// Use ValidatePasswordWithSettings for full deployment-aware validation
	if len(password) < 6 || len(password) > 125 {
		return errors.New("password must be between 6 and 125 characters")
	}
	return nil
}

func (s *AuthService) ValidatePasswordWithSettings(password string, settings model.PasswordSettings) error {
	minLength := settings.MinLength
	if minLength == 0 {
		minLength = 6
	}

	if uint64(len(password)) < minLength {
		return fmt.Errorf("password must be at least %d characters long", minLength)
	}

	if len(password) > 125 {
		return errors.New("password must be at most 125 characters long")
	}

	if settings.RequireLowercase {
		hasLowercase := regexp.MustCompile(`[a-z]`).MatchString(password)
		if !hasLowercase {
			return errors.New("password must contain at least one lowercase letter")
		}
	}

	if settings.RequireUppercase {
		hasUppercase := regexp.MustCompile(`[A-Z]`).MatchString(password)
		if !hasUppercase {
			return errors.New("password must contain at least one uppercase letter")
		}
	}

	if settings.RequireNumber {
		hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
		if !hasNumber {
			return errors.New("password must contain at least one number")
		}
	}

	if settings.RequireSpecialChar {
		hasSymbol := regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password)
		if !hasSymbol {
			return errors.New("password must contain at least one special character")
		}
	}

	return nil
}

func (s *AuthService) SendVerificationEmail(
	deployment *model.Deployment,
	userID uint64,
	email, code, ip, userAgent string,
) error {
	if deployment == nil {
		return fmt.Errorf("deployment is required")
	}

	// If userID is 0, we might want to look it up or just pass 0 if it's a new user verification
	return s.nats.SendVerificationEmail(deployment.ID, userID, email, code, ip, userAgent)
}

func (s *AuthService) SendSignupVerificationEmail(
	signupAttemptID uint64,
	email string,
	code string,
	deployment *model.Deployment,
	userID uint64,
	ip string,
	userAgent string,
) error {
	if deployment == nil {
		return fmt.Errorf("deployment is required")
	}
	return s.nats.SendVerificationEmail(deployment.ID, userID, email, code, ip, userAgent)
}

func (s *AuthService) SendSigninVerificationEmail(
	userID uint64,
	email string,
	code string,
	deployment model.Deployment,
	ip string,
	userAgent string,
) error {
	return s.nats.SendVerificationEmail(deployment.ID, userID, email, code, ip, userAgent)
}

func (s *AuthService) SendPasswordResetEmail(
	deployment *model.Deployment,
	userID uint64,
	email, code, ip, userAgent string,
) error {
	if deployment == nil {
		return fmt.Errorf("deployment is required")
	}

	return s.nats.SendPasswordResetEmail(deployment.ID, userID, email, code, ip, userAgent)
}

func (s *AuthService) SendEmailVerificationEmail(
	userID uint64,
	email string,
	code string,
	deployment *model.Deployment,
	ip string,
	userAgent string,
) error {
	if deployment == nil {
		return fmt.Errorf("deployment is required")
	}
	return s.nats.SendVerificationEmail(deployment.ID, userID, email, code, ip, userAgent)
}

func (s *AuthService) SendSmsOTPVerificationAsync(
	phoneNumber string,
	countryCode string,
	userID uint64,
	deployment model.Deployment,
) error {
	return s.nats.SendOTPSMS(deployment.ID, userID, phoneNumber, countryCode)
}

func (s *AuthService) VerifyPhoneOTP(
	deploymentID uint64,
	phoneNumber string,
	code string,
) (bool, error) {
	return utils.VerifyPhoneOTP(deploymentID, phoneNumber, code)
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

	magicLink := fmt.Sprintf("https://%s/magic?token=%s&attempt=%d",
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
	userEmail, err := s.FindUserByEmail(email, deployment.ID)
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
	valid, err := s.VerifyOTPFromRedis(key, token)
	if err != nil || !valid {
		return errors.New("invalid or expired magic link token")
	}

	s.DeleteOTPFromRedis(key)
	return nil
}

func (s *AuthService) GetRequiredFields(authSettings model.DeploymentAuthSettings) []string {
	var requiredFields []string
	if authSettings.FirstName.Enabled && authSettings.FirstName.Required {
		requiredFields = append(requiredFields, "first_name")
	}
	if authSettings.LastName.Enabled && authSettings.LastName.Required {
		requiredFields = append(requiredFields, "last_name")
	}
	if authSettings.EmailAddress.Enabled && authSettings.EmailAddress.Required {
		requiredFields = append(requiredFields, "email_address")
	}
	if authSettings.Username.Enabled && authSettings.Username.Required {
		requiredFields = append(requiredFields, "username")
	}
	if authSettings.PhoneNumber.Enabled && authSettings.PhoneNumber.Required {
		requiredFields = append(requiredFields, "phone_number")
	}
	return requiredFields
}

func (s *AuthService) CheckMissingRequiredFields(user *model.User, authSettings model.DeploymentAuthSettings) []string {
	var missingFields []string

	if authSettings.FirstName.Enabled && authSettings.FirstName.Required && user.FirstName == "" {
		missingFields = append(missingFields, "first_name")
	}
	if authSettings.LastName.Enabled && authSettings.LastName.Required && user.LastName == "" {
		missingFields = append(missingFields, "last_name")
	}
	if authSettings.Username.Enabled && authSettings.Username.Required && user.Username == "" {
		missingFields = append(missingFields, "username")
	}
	if authSettings.PhoneNumber.Enabled && authSettings.PhoneNumber.Required && user.PrimaryPhoneNumberID == nil {
		missingFields = append(missingFields, "phone_number")
	}

	return missingFields
}

func (s *AuthService) CheckMissingFieldsFromData(
	data model.ProfileCompletionData,
	authSettings model.DeploymentAuthSettings,
) []string {
	var missingFields []string

	if authSettings.FirstName.Enabled && authSettings.FirstName.Required && data.FirstName == "" {
		missingFields = append(missingFields, "first_name")
	}
	if authSettings.LastName.Enabled && authSettings.LastName.Required && data.LastName == "" {
		missingFields = append(missingFields, "last_name")
	}
	if authSettings.EmailAddress.Enabled && authSettings.EmailAddress.Required && data.Email == "" {
		missingFields = append(missingFields, "email_address")
	}
	if authSettings.Username.Enabled && authSettings.Username.Required && data.Username == "" {
		missingFields = append(missingFields, "username")
	}
	if authSettings.PhoneNumber.Enabled && authSettings.PhoneNumber.Required && data.PhoneNumber == "" {
		missingFields = append(missingFields, "phone_number")
	}

	return missingFields
}

func (s *AuthService) ValidateProfileCompletionData(data model.ProfileCompletionData, requiredFields []string) error {
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
	data model.ProfileCompletionData,
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

func (s *AuthService) CheckAndAddUserToOrganizationByDomain(
	tx *gorm.DB,
	userID uint64,
	email string,
	deploymentID uint64,
) error {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil
	}
	domain := parts[1]

	var orgDomain model.OrganizationDomain
	if err := tx.Where("fqdn = ? AND verified = ? AND deployment_id = ?", domain, true, deploymentID).
		First(&orgDomain).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil
		}
		return err
	}

	var org model.Organization
	if err := tx.Where("id = ?", orgDomain.OrganizationID).First(&org).Error; err != nil {
		return err
	}

	// Check if user is already a member
	var count int64
	tx.Model(&model.OrganizationMembership{}).
		Where("organization_id = ? AND user_id = ?", org.ID, userID).
		Count(&count)
	if count > 0 {
		return nil
	}

	membershipID := snowflake.ID()
	membership := model.OrganizationMembership{
		Model:          model.Model{ID: membershipID},
		OrganizationID: org.ID,
		UserID:         userID,
		PublicMetadata: datatypes.JSONMap{},
	}

	if err := tx.Create(&membership).Error; err != nil {
		return err
	}

	if org.AutoAssignedWorkspaceID != nil {
		// Check if user is already a member of the workspace
		tx.Model(&model.WorkspaceMembership{}).
			Where("workspace_id = ? AND user_id = ?", *org.AutoAssignedWorkspaceID, userID).
			Count(&count)

		if count == 0 {
			workspaceMembership := model.WorkspaceMembership{
				Model:                    model.Model{ID: snowflake.ID()},
				WorkspaceID:              *org.AutoAssignedWorkspaceID,
				OrganizationID:           org.ID,
				OrganizationMembershipID: membershipID,
				UserID:                   userID,
				PublicMetadata:           datatypes.JSONMap{},
			}
			if err := tx.Create(&workspaceMembership).Error; err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *AuthService) CreateSignupAttempt(
	b *SignUpRequest,
	hashedPassword string,
	session *model.Session,
	d model.Deployment,
) (*model.SignupAttempt, error) {
	requiredFields := s.GetRequiredFields(d.AuthSettings)

	data := model.ProfileCompletionData{
		FirstName:        b.FirstName,
		LastName:         b.LastName,
		Username:         b.Username,
		Email:            b.Email,
		PhoneNumber:      b.PhoneNumber,
		PhoneCountryCode: b.PhoneCountryCode,
	}

	missingFields := s.CheckMissingFieldsFromData(data, d.AuthSettings)

	var steps []model.SignupAttemptStep

	if d.AuthSettings.EmailAddress.VerifySignup && b.Email != "" {
		steps = append(steps, model.SignupAttemptStepVerifyEmail)
	}
	if d.AuthSettings.PhoneNumber.VerifySignup &&
		b.PhoneNumber != "" {
		steps = append(steps, model.SignupAttemptStepVerifyPhone)
	}

	attempt := &model.SignupAttempt{
		Model: model.Model{
			ID: snowflake.ID(),
		},
		SessionID:        session.ID,
		FirstName:        b.FirstName,
		LastName:         b.LastName,
		Email:            b.Email,
		Username:         b.Username,
		PhoneNumber:      b.PhoneNumber,
		PhoneCountryCode: b.PhoneCountryCode,
		Password:         hashedPassword,
		RequiredFields:   datatypes.NewJSONSlice(requiredFields),
		MissingFields:    datatypes.NewJSONSlice(missingFields),
		RemainingSteps:   datatypes.NewJSONSlice(steps),
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

	data := model.ProfileCompletionData{
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
	if d.AuthSettings.EmailAddress.VerifySignup && email != "" {
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
	ctx := context.Background()
	redisKey := fmt.Sprintf("otp:%s", key)

	// Add OTP to the set
	if err := database.Redis.SAdd(ctx, redisKey, otp).Err(); err != nil {
		return err
	}

	// Set TTL to 90 seconds for the entire set
	return database.Redis.Expire(ctx, redisKey, 90*time.Second).Err()
}

func (s *AuthService) GetOTPFromRedis(key string) (string, error) {
	// This method is deprecated but kept for backward compatibility
	// Use VerifyOTPFromRedis instead
	return database.Redis.Get(
		context.Background(),
		fmt.Sprintf("otp:%s", key),
	).Result()
}

func (s *AuthService) VerifyOTPFromRedis(key string, otp string) (bool, error) {
	ctx := context.Background()
	redisKey := fmt.Sprintf("otp:%s", key)

	// Check if OTP exists in the set
	exists, err := database.Redis.SIsMember(ctx, redisKey, otp).Result()
	if err != nil {
		return false, err
	}

	return exists, nil
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

func (s *AuthService) StoreResetTokenInCache(token string, userID uint64) error {
	return database.Redis.Set(
		context.Background(),
		fmt.Sprintf("reset-token:%s", token),
		userID,
		15*time.Minute,
	).Err()
}

func (s *AuthService) GetUserIDFromResetToken(token string) (uint64, error) {
	val, err := database.Redis.Get(
		context.Background(),
		fmt.Sprintf("reset-token:%s", token),
	).Result()
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(val, 10, 64)
}

func (s *AuthService) DeleteResetTokenFromCache(token string) error {
	return database.Redis.Del(
		context.Background(),
		fmt.Sprintf("reset-token:%s", token),
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
		FirstName:        attempt.FirstName,
		LastName:         attempt.LastName,
		Username:         attempt.Username,
		Email:            attempt.Email,
		PhoneNumber:      attempt.PhoneNumber,
		PhoneCountryCode: attempt.PhoneCountryCode,
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
	validityPeriodSeconds uint64,
) *model.Signin {
	signIn := model.NewSignIn(sessionID, userID, validityPeriodSeconds)
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
	signIn.LastActiveAt = time.Now()

	return signIn
}

func (s *AuthService) TrackMAU(deploymentID, userID uint64) {
	go s.nats.PublishBillingEvent(deploymentID, userID, "mau")
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

	resp, err := client.Get("https://freeipapi.com/api/json/" + ip)
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

	var response struct {
		IPVersion     int      `json:"ipVersion"`
		IPAddress     string   `json:"ipAddress"`
		Latitude      float64  `json:"latitude"`
		Longitude     float64  `json:"longitude"`
		CountryName   string   `json:"countryName"`
		CountryCode   string   `json:"countryCode"`
		Capital       string   `json:"capital"`
		PhoneCodes    []int    `json:"phoneCodes"`
		TimeZones     []string `json:"timeZones"`
		ZipCode       string   `json:"zipCode"`
		CityName      string   `json:"cityName"`
		RegionName    string   `json:"regionName"`
		Continent     string   `json:"continent"`
		ContinentCode string   `json:"continentCode"`
		Currencies    []string `json:"currencies"`
		Languages     []string `json:"languages"`
		IsProxy       bool     `json:"isProxy"`
	}

	err = json.Unmarshal(body, &response)
	if err != nil {
		return defaultLocation
	}

	// Basic validation to consider it a success
	if response.CountryCode == "" {
		return defaultLocation
	}

	timezone := ""
	if len(response.TimeZones) > 0 {
		timezone = response.TimeZones[0]
	}

	return IPLocation{
		Status:        "success",
		Country:       response.CountryName,
		CountryCode:   response.CountryCode,
		Region:        response.RegionName, // freeipapi doesn't provide region code in main response
		RegionName:    response.RegionName,
		City:          response.CityName,
		Zip:           response.ZipCode,
		Lat:           response.Latitude,
		Long:          response.Longitude,
		Timezone:      timezone,
		Continent:     response.Continent,
		ContinentCode: response.ContinentCode,
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
		if service.IsDisposableEmailDomain(email) {
			return handler.ErrDisposableEmail
		}
	}

	if err := s.validateEmailMXRecord(email); err != nil {
		return handler.ErrEmailNotAllowed
	}

	return nil
}

func (s *AuthService) ValidatePhoneRestrictions(phoneNumber string, restrictions model.DeploymentRestrictions) error {
	abstractAPIService := service.NewAbstractAPIService(
		config.GetEnv("ABSTRACT_API_KEY", ""),
	)

	if abstractAPIService.APIKey != "" {
		result, err := abstractAPIService.ValidatePhoneNumber(phoneNumber)
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
			allowed := slices.Contains(restrictions.CountryRestrictions.CountryCodes, result.CountryCode)
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
		allowed := slices.Contains(restrictions.CountryRestrictions.CountryCodes, countryCode)
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

	allowed := slices.Contains(restrictions.CountryRestrictions.CountryCodes, ipLocation.CountryCode)

	if !allowed {
		return handler.ErrCountryRestricted
	}

	return nil
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
	data model.ProfileCompletionData,
	userID *uint64,
	authSettings model.DeploymentAuthSettings,
) []string {
	var steps []string

	if data.Email != "" && authSettings.EmailAddress.VerifySignup {
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

	if data.PhoneNumber != "" && authSettings.PhoneNumber.VerifySignup {
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

func (s *AuthService) GetAvailable2FAMethods(userID uint64, deployment *model.Deployment) []string {
	var methods []string

	var phoneCount int64
	s.db.Model(&model.UserPhoneNumber{}).
		Where("user_id = ? AND verified = true", userID).
		Count(&phoneCount)
	if phoneCount > 0 {
		methods = append(methods, "phone_otp")
	}

	if deployment.AuthSettings.AuthFactorsEnabled.Authenticator {
		var authenticatorCount int64
		s.db.Model(&model.UserAuthenticator{}).
			Where("user_id = ?", userID).
			Count(&authenticatorCount)
		if authenticatorCount > 0 {
			methods = append(methods, "authenticator")
		}
	}

	var user model.User
	if err := s.db.Select("backup_codes").Where("id = ?", userID).First(&user).Error; err == nil {
		if len(user.BackupCodes) > 0 {
			methods = append(methods, "backup_code")
		}
	}

	return methods
}
