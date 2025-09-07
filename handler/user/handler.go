package user

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/godruoyi/go-snowflake"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/utils"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"gorm.io/datatypes"
	"gorm.io/plugin/dbresolver"
)

type Handler struct {
	service *UserService
}

func NewHandler() *Handler {
	return &Handler{
		service: NewUserService(),
	}
}

// JSON parsing structs to handle string IDs from SQL
type userEmailAddressJSON struct {
	ID                   string `json:"id"`
	CreatedAt            string `json:"created_at"`
	UpdatedAt            string `json:"updated_at"`
	EmailAddress         string `json:"email_address"`
	IsPrimary            bool   `json:"is_primary"`
	Verified             bool   `json:"verified"`
	VerifiedAt           string `json:"verified_at"`
	VerificationStrategy string `json:"verification_strategy"`
}

type userPhoneNumberJSON struct {
	ID          string `json:"id"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	PhoneNumber string `json:"phone_number"`
	Verified    bool   `json:"verified"`
	VerifiedAt  string `json:"verified_at"`
}

type socialConnectionJSON struct {
	ID                 string `json:"id"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
	UserEmailAddressID string `json:"user_email_address_id"`
	Provider           string `json:"provider"`
	EmailAddress       string `json:"email_address"`
	FirstName          string `json:"first_name"`
	LastName           string `json:"last_name"`
}

type userAuthenticatorJSON struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	UserID    string `json:"user_id"`
	OtpUrl    string `json:"otp_url"`
}

// parseUserEmailAddressesJSON parses the JSON string into a slice of UserEmailAddress
// Handles JSON parsing errors gracefully without breaking the response
func parseUserEmailAddressesJSON(jsonStr string) []model.UserEmailAddress {
	// Handle empty, null, or empty array cases
	if jsonStr == "" || jsonStr == "[]" || jsonStr == "null" {
		return []model.UserEmailAddress{}
	}

	var jsonEmails []userEmailAddressJSON
	if err := json.Unmarshal([]byte(jsonStr), &jsonEmails); err != nil {
		log.Printf("Error parsing user email addresses JSON: %v, JSON: %s", err, jsonStr)
		// Return empty slice to maintain backward compatibility and prevent response failure
		return []model.UserEmailAddress{}
	}

	var emailAddresses []model.UserEmailAddress
	for _, jsonEmail := range jsonEmails {

		id, err := strconv.ParseUint(jsonEmail.ID, 10, 64)
		if err != nil {
			log.Printf("Error parsing email address ID '%s': %v", jsonEmail.ID, err)
			continue
		}

		createdAt, _ := time.Parse(time.RFC3339, jsonEmail.CreatedAt)
		updatedAt, _ := time.Parse(time.RFC3339, jsonEmail.UpdatedAt)
		verifiedAt, _ := time.Parse(time.RFC3339, jsonEmail.VerifiedAt)

		emailAddresses = append(emailAddresses, model.UserEmailAddress{
			Model: model.Model{
				ID:        id,
				CreatedAt: createdAt,
				UpdatedAt: updatedAt,
			},
			EmailAddress:         jsonEmail.EmailAddress,
			IsPrimary:            jsonEmail.IsPrimary,
			Verified:             jsonEmail.Verified,
			VerifiedAt:           verifiedAt,
			VerificationStrategy: model.VerificationStrategy(jsonEmail.VerificationStrategy),
		})
	}

	return emailAddresses
}

// parseUserPhoneNumbersJSON parses the JSON string into a slice of UserPhoneNumber
// Handles JSON parsing errors gracefully without breaking the response
func parseUserPhoneNumbersJSON(jsonStr string) []model.UserPhoneNumber {
	// Handle empty, null, or empty array cases
	if jsonStr == "" || jsonStr == "[]" || jsonStr == "null" {
		return []model.UserPhoneNumber{}
	}

	var jsonPhones []userPhoneNumberJSON
	if err := json.Unmarshal([]byte(jsonStr), &jsonPhones); err != nil {
		log.Printf("Error parsing user phone numbers JSON: %v, JSON: %s", err, jsonStr)
		// Return empty slice to maintain backward compatibility and prevent response failure
		return []model.UserPhoneNumber{}
	}

	var phoneNumbers []model.UserPhoneNumber
	for _, jsonPhone := range jsonPhones {

		id, err := strconv.ParseUint(jsonPhone.ID, 10, 64)
		if err != nil {
			log.Printf("Error parsing phone number ID '%s': %v", jsonPhone.ID, err)
			continue
		}

		createdAt, _ := time.Parse(time.RFC3339, jsonPhone.CreatedAt)
		updatedAt, _ := time.Parse(time.RFC3339, jsonPhone.UpdatedAt)
		verifiedAt, _ := time.Parse(time.RFC3339, jsonPhone.VerifiedAt)

		phoneNumbers = append(phoneNumbers, model.UserPhoneNumber{
			Model: model.Model{
				ID:        id,
				CreatedAt: createdAt,
				UpdatedAt: updatedAt,
			},
			PhoneNumber: jsonPhone.PhoneNumber,
			Verified:    jsonPhone.Verified,
			VerifiedAt:  verifiedAt,
		})
	}

	return phoneNumbers
}

// parseSocialConnectionsJSON parses the JSON string into a slice of SocialConnection
// Handles JSON parsing errors gracefully without breaking the response
func parseSocialConnectionsJSON(jsonStr string) []model.SocialConnection {
	// Handle empty, null, or empty array cases
	if jsonStr == "" || jsonStr == "[]" || jsonStr == "null" {
		return []model.SocialConnection{}
	}

	var jsonConnections []socialConnectionJSON
	if err := json.Unmarshal([]byte(jsonStr), &jsonConnections); err != nil {
		log.Printf("Error parsing social connections JSON: %v, JSON: %s", err, jsonStr)
		// Return empty slice to maintain backward compatibility and prevent response failure
		return []model.SocialConnection{}
	}

	var socialConnections []model.SocialConnection
	for _, jsonConn := range jsonConnections {

		id, err := strconv.ParseUint(jsonConn.ID, 10, 64)
		if err != nil {
			log.Printf("Error parsing social connection ID '%s': %v", jsonConn.ID, err)
			continue
		}

		userEmailAddressID, err := strconv.ParseUint(jsonConn.UserEmailAddressID, 10, 64)
		if err != nil {
			log.Printf("Error parsing social connection user_email_address_id '%s': %v", jsonConn.UserEmailAddressID, err)
			continue
		}

		createdAt, _ := time.Parse(time.RFC3339, jsonConn.CreatedAt)
		updatedAt, _ := time.Parse(time.RFC3339, jsonConn.UpdatedAt)

		socialConnections = append(socialConnections, model.SocialConnection{
			Model: model.Model{
				ID:        id,
				CreatedAt: createdAt,
				UpdatedAt: updatedAt,
			},
			UserEmailAddressID: userEmailAddressID,
			Provider:           model.SocialConnectionProvider(jsonConn.Provider),
			EmailAddress:       jsonConn.EmailAddress,
			FirstName:          jsonConn.FirstName,
			LastName:           jsonConn.LastName,
		})
	}

	return socialConnections
}

// parseUserAuthenticatorJSON parses the JSON string into a UserAuthenticator pointer
// Handles JSON parsing errors gracefully without breaking the response
func parseUserAuthenticatorJSON(jsonStr string) *model.UserAuthenticator {
	// Handle empty or null cases
	if jsonStr == "" || jsonStr == "null" {
		return nil
	}

	var jsonAuth userAuthenticatorJSON
	if err := json.Unmarshal([]byte(jsonStr), &jsonAuth); err != nil {
		log.Printf("Error parsing user authenticator JSON: %v, JSON: %s", err, jsonStr)
		// Return nil to maintain backward compatibility and prevent response failure
		return nil
	}

	// Parse fields with error handling - return nil if critical fields fail to parse
	id, err := strconv.ParseUint(jsonAuth.ID, 10, 64)
	if err != nil {
		log.Printf("Error parsing user authenticator ID '%s': %v", jsonAuth.ID, err)
		return nil
	}

	userID, err := strconv.ParseUint(jsonAuth.UserID, 10, 64)
	if err != nil {
		log.Printf("Error parsing user authenticator user_id '%s': %v", jsonAuth.UserID, err)
		return nil
	}

	createdAt, _ := time.Parse(time.RFC3339, jsonAuth.CreatedAt)
	updatedAt, _ := time.Parse(time.RFC3339, jsonAuth.UpdatedAt)

	return &model.UserAuthenticator{
		Model: model.Model{
			ID:        id,
			CreatedAt: createdAt,
			UpdatedAt: updatedAt,
		},
		UserID: &userID,
		OtpUrl: jsonAuth.OtpUrl,
	}
}

func (h *Handler) GetUser(c *fiber.Ctx) error {
	session := handler.GetSession(c)

	// Validate session exists
	if session == nil {
		return handler.SendUnauthorized(
			c,
			nil,
			"Unauthorized",
		)
	}

	var queryResult UserQueryResult
	rawSQL := `
		SELECT
			u.id as user_id,
			u.created_at as user_created_at,
			u.updated_at as user_updated_at,
			u.first_name,
			u.last_name,
			u.username,
			u.has_profile_picture,
			u.profile_picture_url,
			u.availability,
			u.last_password_reset_at,
			u.schema_version,
			u.disabled,
			u.primary_email_address_id,
			u.primary_phone_number_id,
			u.second_factor_policy,
			u.active_organization_membership_id,
			u.active_workspace_membership_id,
			u.public_metadata,
			u.backup_codes_generated,
			CASE WHEN u.password != '' AND u.password IS NOT NULL THEN true ELSE false END as has_password,

			-- JSON aggregation for related data
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', uea.id::text,
						'created_at', uea.created_at,
						'updated_at', uea.updated_at,
						'email_address', uea.email_address,
						'is_primary', uea.is_primary,
						'verified', uea.verified,
						'verified_at', uea.verified_at,
						'verification_strategy', uea.verification_strategy
					)
				)
				FROM user_email_addresses uea
				WHERE uea.user_id = u.id AND uea.deleted_at IS NULL
				), '[]'::json
			) as user_email_addresses_json,

			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', upn.id::text,
						'created_at', upn.created_at,
						'updated_at', upn.updated_at,
						'phone_number', upn.phone_number,
						'verified', upn.verified,
						'verified_at', upn.verified_at
					)
				)
				FROM user_phone_numbers upn
				WHERE upn.user_id = u.id AND upn.deleted_at IS NULL
				), '[]'::json
			) as user_phone_numbers_json,

			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', sc.id::text,
						'created_at', sc.created_at,
						'updated_at', sc.updated_at,
						'user_email_address_id', sc.user_email_address_id::text,
						'provider', sc.provider,
						'email_address', sc.email_address,
						'first_name', sc.first_name,
						'last_name', sc.last_name
					)
				)
				FROM social_connections sc
				WHERE sc.user_id = u.id AND sc.deleted_at IS NULL
				), '[]'::json
			) as social_connections_json,

			COALESCE(
				(SELECT json_build_object(
					'id', ua.id::text,
					'created_at', ua.created_at,
					'updated_at', ua.updated_at,
					'user_id', ua.user_id::text,
					'otp_url', ua.otp_url
				)
				FROM user_authenticators ua
				WHERE ua.user_id = u.id AND ua.deleted_at IS NULL
				LIMIT 1
				), 'null'::json
			) as user_authenticator_json

		FROM sessions s
		JOIN signins si ON s.active_signin_id = si.id
		JOIN users u ON si.user_id = u.id
		WHERE s.id = ? AND s.deleted_at IS NULL AND si.deleted_at IS NULL AND u.deleted_at IS NULL
	`

	// Execute the optimized query with proper error handling
	if err := database.Connection.Clauses(dbresolver.Read).Raw(rawSQL, session.ID).Scan(&queryResult).Error; err != nil {
		log.Printf("Database error in GetUser: %v", err)
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	// Check if we got a result - this handles the case where no active sign-in is found
	if queryResult.UserID == 0 {
		return handler.SendBadRequest(
			c,
			nil,
			"No active sign-in found",
		)
	}

	// Parse JSON fields and construct User model with error handling
	user := model.User{
		Model: model.Model{
			ID:        queryResult.UserID,
			CreatedAt: queryResult.UserCreatedAt,
			UpdatedAt: queryResult.UserUpdatedAt,
		},
		FirstName:                      queryResult.FirstName,
		LastName:                       queryResult.LastName,
		Username:                       queryResult.Username,
		HasProfilePicture:              queryResult.HasProfilePicture,
		ProfilePictureURL:              queryResult.ProfilePictureURL,
		Availability:                   model.UserAvailability(queryResult.Availability),
		LastPasswordResetAt:            queryResult.LastPasswordResetAt,
		SchemaVersion:                  model.SchemaVersion(queryResult.SchemaVersion),
		Disabled:                       queryResult.Disabled,
		PrimaryEmailAddressID:          queryResult.PrimaryEmailAddressID,
		PrimaryPhoneNumberID:           queryResult.PrimaryPhoneNumberID,
		SecondFactorPolicy:             model.SecondFactorPolicy(queryResult.SecondFactorPolicy),
		ActiveOrganizationMembershipID: queryResult.ActiveOrganizationMembershipID,
		ActiveWorkspaceMembershipID:    queryResult.ActiveWorkspaceMembershipID,
		PublicMetadata:                 make(datatypes.JSONMap),
		BackupCodesGenerated:           queryResult.BackupCodesGenerated,
	}

	// Parse JSON fields using helper functions - these functions handle JSON parsing errors gracefully
	// by logging errors and returning empty collections to maintain backward compatibility
	user.UserEmailAddresses = parseUserEmailAddressesJSON(queryResult.UserEmailAddressesJSON)
	user.UserPhoneNumbers = parseUserPhoneNumbersJSON(queryResult.UserPhoneNumbersJSON)
	user.SocialConnections = parseSocialConnectionsJSON(queryResult.SocialConnectionsJSON)
	user.UserAuthenticator = parseUserAuthenticatorJSON(queryResult.UserAuthenticatorJSON)

	// Parse PublicMetadata JSON with error handling
	if queryResult.PublicMetadata != "" && queryResult.PublicMetadata != "null" {
		var metadata datatypes.JSONMap
		if err := json.Unmarshal([]byte(queryResult.PublicMetadata), &metadata); err != nil {
			log.Printf("Error parsing PublicMetadata JSON in GetUser: %v, JSON: %s", err, queryResult.PublicMetadata)
			// Continue with empty metadata to maintain backward compatibility
			user.PublicMetadata = make(datatypes.JSONMap)
		} else {
			user.PublicMetadata = metadata
		}
	}

	type UserResponse struct {
		model.User
		HasPassword bool `json:"has_password"`
	}

	response := UserResponse{
		User:        user,
		HasPassword: queryResult.HasPassword,
	}

	return handler.SendSuccess(c, response)
}

func (h *Handler) UpdateUser(c *fiber.Ctx) error {
	session := handler.GetSession(c)

	b, validation := handler.Validate[UpdateUserSchema](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	updates := make(map[string]any)

	if b.FirstName != "" {
		updates["first_name"] = b.FirstName
	}

	if b.LastName != "" {
		updates["last_name"] = b.LastName
	}

	if b.Username != "" {
		updates["username"] = b.Username
	}

	if b.PrimaryEmailAddressID != "" {
		updates["primary_email_address_id"] = b.PrimaryEmailAddressID
	}

	if b.PrimaryPhoneNumberID != "" {
		updates["primary_phone_number_id"] = b.PrimaryPhoneNumberID
	}

	if b.SecondFactorPolicy != "" {
		updates["second_factor_policy"] = b.SecondFactorPolicy
	}

	query := database.Connection.Model(&model.User{}).
		Where("id = ?", session.ActiveSignin.UserID).
		Updates(updates)

	if err := query.Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	return c.SendStatus(fiber.StatusOK)
}

func (h *Handler) GetUserEmailAddresses(c *fiber.Ctx) error {
	session := handler.GetSession(c)

	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	var emailAddresses []model.UserEmailAddress

	query := database.Connection.Model(&model.UserEmailAddress{}).
		Where("user_id = ?", session.ActiveSignin.UserID).
		Find(&emailAddresses)

	if err := query.Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	return handler.SendSuccess(c, emailAddresses)
}

func (h *Handler) GetUserEmailAddress(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	emailID := c.Params("id")
	if emailID == "" {
		return handler.SendBadRequest(
			c,
			nil,
			"Email address ID is required",
		)
	}

	var email model.UserEmailAddress
	query := database.Connection.Where("id = ? AND user_id = ?", emailID, session.ActiveSignin.UserID).
		First(&email)
	if query.Error != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	return handler.SendSuccess(c, email)
}

func (h *Handler) DeleteUserEmailAddress(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	emailID := c.Params("id")
	if emailID == "" {
		return handler.SendBadRequest(
			c,
			nil,
			"Email address ID is required",
		)
	}

	query := database.Connection.Where("id = ? AND user_id = ? AND is_primary = ?", emailID, session.ActiveSignin.UserID, false).
		Delete(&model.UserEmailAddress{})
	if query.Error != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	// Check if any rows were affected (deleted)
	if query.RowsAffected == 0 {
		return handler.SendBadRequest(
			c,
			nil,
			"Cannot delete primary email address or email not found.",
		)
	}

	return handler.SendSuccess(c, "Deleted successfully")
}

func (h *Handler) CreateUserEmailAddress(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	b, validation := handler.Validate[AddUserEmailAddressSchema](c)

	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	deployment := handler.GetDeployment(c)

	if err := h.service.ValidateEmailRestrictions(b.Email, deployment.Restrictions); err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	newEmail := model.UserEmailAddress{
		Model: model.Model{
			ID: snowflake.ID(),
		},
		DeploymentID: deployment.ID,
		UserID:       session.ActiveSignin.UserID,
		EmailAddress: b.Email,
		Verified:     false,
	}

	query := database.Connection.Create(&newEmail)
	if query.Error != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	return handler.SendSuccess(c, newEmail)
}

func (h *Handler) AttemptEmailVerification(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	emailID := c.Params("id")
	if emailID == "" {
		return handler.SendBadRequest(
			c,
			nil,
			"Email address ID is required",
		)
	}

	emailAddress := model.UserEmailAddress{}
	if err := database.Connection.Where("id = ? AND user_id = ?", emailID, session.ActiveSignin.UserID).First(&emailAddress).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	providedCode := c.Query("code")
	if providedCode == "" {
		return handler.SendBadRequest(c, nil, "OTP code is required")
	}

	expectedOTP, err := h.service.getOTPFromCache(
		strconv.Itoa(int(emailAddress.ID)),
	)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	if providedCode != expectedOTP {
		return handler.SendBadRequest(c, nil, "Invalid OTP code")
	}

	if err = h.service.removeOTPFromCache(strconv.Itoa(int(emailAddress.ID))); err != nil {
	}

	emailAddress.Verified = true
	if err = database.Connection.Save(&emailAddress).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	return handler.SendSuccess(c, "Email verified successfully")
}

func (h *Handler) PrepareEmailVerification(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	deployment := handler.GetDeployment(c)

	emailID := c.Params("id")
	if emailID == "" {
		return handler.SendBadRequest(
			c,
			nil,
			"Email address ID is required",
		)
	}

	emailAddress := model.UserEmailAddress{}
	if err := database.Connection.Where("id = ? AND user_id = ?", emailID, session.ActiveSignin.UserID).First(&emailAddress).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	session.ActiveSignin.LoadUser(database.Connection)

	code, err := utils.GenerateOTP()
	if err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	err = h.service.storeOTPInCache(
		strconv.Itoa(int(emailAddress.ID)),
		code,
	)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	err = h.service.sendEmailOTPVerificationAsync(
		deployment.ID,
		emailAddress,
		code,
	)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	return handler.SendSuccess(c, "Verification code sent successfully")
}

func (h *Handler) GetUserPhoneNumbers(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	var phoneNumbers []model.UserPhoneNumber
	query := database.Connection.Model(&model.UserPhoneNumber{}).
		Where("user_id = ?", session.ActiveSignin.UserID).
		Find(&phoneNumbers)
	if query.Error != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	return handler.SendSuccess(c, phoneNumbers)
}

func (h *Handler) GetPhoneNumber(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	phoneID := c.Params("id")
	if phoneID == "" {
		return handler.SendBadRequest(
			c,
			nil,
			"Phone number ID is required",
		)
	}

	var phoneNumber model.UserPhoneNumber
	query := database.Connection.Where("id = ? AND user_id = ?", phoneID, session.ActiveSignin.UserID).
		First(&phoneNumber)
	if query.Error != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	return handler.SendSuccess(c, phoneNumber)
}

func (h *Handler) AddPhoneNumber(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	b, validation := handler.Validate[AddUserPhoneNumberSchema](c)

	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	deployment := handler.GetDeployment(c)

	if err := h.service.ValidatePhoneRestrictions(b.PhoneNumber, deployment.Restrictions); err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	phoneNumber := model.UserPhoneNumber{
		Model: model.Model{
			ID: snowflake.ID(),
		},
		PhoneNumber: b.PhoneNumber,
	}

	phoneNumber.UserID = *session.ActiveSignin.UserID

	if err := database.Connection.Create(&phoneNumber).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	return handler.SendSuccess(c, phoneNumber)
}

func (h *Handler) PreparePhoneVerification(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	deployment := handler.GetDeployment(c)

	phoneID := c.Params("id")
	if phoneID == "" {
		return handler.SendBadRequest(
			c,
			nil,
			"Phone number ID is required",
		)
	}

	phoneNumber := model.UserPhoneNumber{}
	if err := database.Connection.Where("id = ? AND user_id = ?", phoneID, session.ActiveSignin.UserID).First(&phoneNumber).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	session.ActiveSignin.LoadUser(database.Connection)

	code, err := utils.GenerateOTP()
	if err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	err = h.service.storeOTPInCache(
		strconv.Itoa(int(phoneNumber.ID)),
		code,
	)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	err = h.service.sendSmsOTPVerificationAsync(
		deployment.ID,
		phoneNumber.PhoneNumber,
	)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	return handler.SendSuccess(c, "Verification code sent successfully")
}

func (h *Handler) AttemptPhoneVerification(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	phoneID := c.Params("id")
	if phoneID == "" {
		return handler.SendBadRequest(
			c,
			nil,
			"Phone number ID is required",
		)
	}

	phoneNumber := model.UserPhoneNumber{}
	if err := database.Connection.Where("id = ? AND user_id = ?", phoneID, session.ActiveSignin.UserID).First(&phoneNumber).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	providedCode := c.Query("code")
	if providedCode == "" {
		return handler.SendBadRequest(c, nil, "OTP code is required")
	}

	expectedOTP, err := h.service.getOTPFromCache(
		strconv.Itoa(int(phoneNumber.ID)),
	)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	if providedCode != expectedOTP {
		return handler.SendBadRequest(c, nil, "Invalid OTP code")
	}

	if err = h.service.removeOTPFromCache(strconv.Itoa(int(phoneNumber.ID))); err != nil {
	}

	phoneNumber.Verified = true
	phoneNumber.VerifiedAt = time.Now().UTC()
	if err = database.Connection.Save(&phoneNumber).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	return handler.SendSuccess(c, "Phone number verified successfully")
}

func (h *Handler) DeletePhoneNumber(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	phoneID := c.Params("id")
	if phoneID == "" {
		return handler.SendBadRequest(
			c,
			nil,
			"Phone number ID is required",
		)
	}

	query := database.Connection.Where("id = ? AND user_id = ?", phoneID, session.ActiveSignin.UserID).
		Delete(&model.UserPhoneNumber{})
	if query.Error != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	return handler.SendSuccess(c, "Deleted successfully")
}

func (h *Handler) GenerateAuthenticator(c *fiber.Ctx) error {
	deployment := handler.GetDeployment(c)
	session := handler.GetSession(c)

	if session == nil || session.ActiveSignin == nil || session.ActiveSignin.User == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	var accountName string
	user := session.ActiveSignin.User

	if user.FirstName != "" || user.LastName != "" {
		name := strings.TrimSpace(user.FirstName + " " + user.LastName)
		accountName = fmt.Sprintf("%s (%d)", name, session.ActiveSignin.UserID)
	} else if user.PrimaryEmailAddress != nil {
		accountName = fmt.Sprintf("%s (%d)", user.PrimaryEmailAddress.EmailAddress, session.ActiveSignin.UserID)
	} else {
		accountName = fmt.Sprintf("User (%d)", session.ActiveSignin.UserID)
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      deployment.UISettings.AppName,
		AccountName: accountName,
		SecretSize:  20,
	})
	if err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to generate authenticator",
			handler.ErrInternal,
		)
	}

	authenticator := &model.UserAuthenticator{
		Model: model.Model{
			ID: snowflake.ID(),
		},
		TotpSecret: key.Secret(),
		OtpUrl:     key.URL(),
	}

	if err := database.Connection.Create(authenticator).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to save authenticator",
			handler.ErrInternal,
		)
	}

	resp := map[string]any{
		"id":          strconv.Itoa(int(authenticator.ID)),
		"otp_url":     authenticator.OtpUrl,
		"totp_secret": authenticator.TotpSecret,
		"created_at":  authenticator.CreatedAt,
	}

	return handler.SendSuccess(c, resp)
}

func (h *Handler) VerifyAuthenticator(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	b, validation := handler.Validate[VerifyAuthenticatorSchema](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	var authenticator model.UserAuthenticator
	if err := database.Connection.Where("id = ?", b.AuthenticatorID).First(&authenticator).Error; err != nil {
		return handler.SendBadRequest(
			c,
			nil,
			"Invalid authenticator ID",
		)
	}

	if authenticator.UserID != nil {
		return handler.SendBadRequest(
			c,
			nil,
			"Authenticator already linked to a user",
		)
	}

	firstCode := b.Codes[0]
	secondCode := b.Codes[1]

	valid, err := totp.ValidateCustom(
		firstCode,
		authenticator.TotpSecret,
		time.Now().Add(-time.Second*30),
		totp.ValidateOpts{
			Period: 30,
			Digits: otp.DigitsSix,
		},
	)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to validate first code",
		)
	}

	if !valid {
		return handler.SendBadRequest(
			c,
			nil,
			"Invalid code",
		)
	}

	valid, err = totp.ValidateCustom(
		secondCode,
		authenticator.TotpSecret,
		time.Now(),
		totp.ValidateOpts{
			Period: 30,
			Digits: otp.DigitsSix,
		},
	)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to validate second code",
			handler.ErrInternal,
		)
	}

	if !valid {
		return handler.SendBadRequest(
			c,
			nil,
			"Invalid code",
		)
	}

	authenticator.UserID = session.ActiveSignin.UserID
	if err := database.Connection.Save(&authenticator).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to link authenticator",
			handler.ErrInternal,
		)
	}

	return handler.SendSuccess(c, authenticator)
}

func (h *Handler) DeleteAuthenticator(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	authenticatorID := c.Params("id")
	if authenticatorID == "" {
		return handler.SendBadRequest(
			c,
			nil,
			"Authenticator ID is required",
		)
	}

	query := database.Connection.Where("id = ? AND user_id = ?", authenticatorID, session.ActiveSignin.UserID).
		Delete(&model.UserAuthenticator{})
	if query.Error != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to delete authenticator",
			handler.ErrInternal,
		)
	}

	return handler.SendSuccess(c, "Authenticator deleted successfully")
}

func (h *Handler) GenerateBackupCodes(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	const codeCount = 12
	const codeLength = 8
	backupCodes := make([]string, codeCount)

	user := model.User{}
	if err := database.Connection.First(&user, session.ActiveSignin.UserID).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to load user",
			handler.ErrInternal,
		)
	}

	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"

	randomBytes := make([]byte, codeLength)

	for i := range codeCount {
		var code string
		for len(code) < codeLength {
			_, err := rand.Read(randomBytes)
			if err != nil {
				return handler.SendInternalServerError(
					c,
					nil,
					"Failed to generate backup codes",
					handler.ErrInternal,
				)
			}

			for _, b := range randomBytes {
				if idx := int(b) % len(charset); len(code) < codeLength {
					code += string(charset[idx])
				}
			}
		}

		if len(code) >= codeLength {
			formattedCode := code[:4] + "-" + code[4:codeLength]
			backupCodes[i] = formattedCode
		}
	}

	if err := database.Connection.Model(&model.User{}).Where("id = ?", session.ActiveSignin.UserID).Updates(map[string]interface{}{
		"backup_codes":           backupCodes,
		"backup_codes_generated": true,
	}).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to save backup codes",
			handler.ErrInternal,
		)
	}

	return handler.SendSuccess(c, backupCodes)
}

func (h *Handler) RegenerateBackupCodes(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	const codeCount = 12
	const codeLength = 8
	backupCodes := make([]string, codeCount)

	user := model.User{}
	if err := database.Connection.First(&user, session.ActiveSignin.UserID).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to load user",
			handler.ErrInternal,
		)
	}

	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"

	randomBytes := make([]byte, codeLength)

	for i := range codeCount {
		var code string
		for len(code) < codeLength {
			_, err := rand.Read(randomBytes)
			if err != nil {
				return handler.SendInternalServerError(
					c,
					nil,
					"Failed to regenerate backup codes",
					handler.ErrInternal,
				)
			}

			for _, b := range randomBytes {
				if idx := int(b) % len(charset); len(code) < codeLength {
					code += string(charset[idx])
				}
			}
		}

		if len(code) >= codeLength {
			formattedCode := code[:4] + "-" + code[4:codeLength]
			backupCodes[i] = formattedCode
		}
	}

	if err := database.Connection.Model(&model.User{}).Where("id = ?", session.ActiveSignin.UserID).Updates(map[string]interface{}{
		"backup_codes":           backupCodes,
		"backup_codes_generated": true,
	}).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to save regenerated backup codes",
			handler.ErrInternal,
		)
	}

	return handler.SendSuccess(c, backupCodes)
}

func (h *Handler) GetUserSignins(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	var signins []model.Signin

	// First, let's get all signins for this user to debug
	var allSignins []model.Signin
	if err := database.Connection.Where("user_id = ?", session.ActiveSignin.UserID).Find(&allSignins).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to get user sessions",
			handler.ErrInternal,
		)
	}

	// Now get the filtered signins
	if err := database.Connection.Where("user_id = ? AND (expires_at > ? OR expires_at IS NULL)", session.ActiveSignin.UserID, time.Now()).Find(&signins).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to get user sessions",
			handler.ErrInternal,
		)
	}

	return handler.SendSuccess(c, signins)
}

func (h *Handler) UploadProfilePicture(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	user := model.User{}
	if err := database.Connection.First(&user, session.ActiveSignin.UserID).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to load user",
		)
	}

	file, err := c.FormFile("file")
	if err != nil {
		return handler.SendBadRequest(c, nil, "File is required")
	}

	url, err := h.service.uploadProfilePicture(*session.ActiveSignin.UserID, file)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to upload profile picture",
			handler.ErrInternal,
		)
	}

	if err := database.Connection.Model(&model.User{}).Where("id = ?", session.ActiveSignin.UserID).Updates(map[string]interface{}{
		"profile_picture_url": url,
		"has_profile_picture": true,
	}).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to save user",
		)
	}
	return handler.SendSuccess[any](c, nil)
}

func (h *Handler) SignOutFromSession(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	signinID := c.Params("id")
	if signinID == "" {
		return handler.SendBadRequest(c, nil, "Signin ID is required")
	}

	signin := model.Signin{}
	if err := database.Connection.Where("id = ? AND user_id = ?", signinID, session.ActiveSignin.UserID).First(&signin).Error; err != nil {
		return handler.SendBadRequest(c, nil, "Failed to find signin")
	}

	signin.ExpiresAt = time.Now().UTC()
	if err := database.Connection.Save(&signin).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to sign out from session",
			handler.ErrInternal,
		)
	}

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess[any](c, nil)
}

func (h *Handler) GetUserOrganizationMemberships(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	var queryResults []OrganizationMembershipQueryResult
	rawSQL := `
		SELECT
			organization_memberships.id,
			organization_memberships.created_at,
			organization_memberships.updated_at,
			organization_memberships.organization_id,
			organization_memberships.user_id,
			organizations.name as organization_name,
			organizations.image_url as organization_image_url,
			organizations.description as organization_description,
			organizations.member_count as organization_member_count,
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', organization_roles.id,
						'organization_id', organization_roles.organization_id,
						'name', organization_roles.name,
						'permissions', organization_roles.permissions,
						'deployment_id', organization_roles.deployment_id,
						'created_at', organization_roles.created_at,
						'updated_at', organization_roles.updated_at
					) ORDER BY organization_roles.name
				)
				FROM organization_membership_roles
				JOIN organization_roles ON organization_membership_roles.organization_role_id = organization_roles.id
				WHERE organization_membership_roles.organization_membership_id = organization_memberships.id
				), '[]'::json
			) as roles_json
		FROM organization_memberships
		JOIN organizations ON organization_memberships.organization_id = organizations.id
		WHERE organization_memberships.user_id = ?
			AND organization_memberships.deleted_at IS NULL
			AND organizations.deleted_at IS NULL
		ORDER BY organization_memberships.created_at DESC
	`

	if err := database.Connection.Clauses(dbresolver.Read).Raw(rawSQL, session.ActiveSignin.UserID).Scan(&queryResults).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to get user organization memberships")
	}

	memberships := make([]model.OrganizationMembership, len(queryResults))
	for i, result := range queryResults {
		memberships[i] = result.OrganizationMembership
		memberships[i].Organization = model.Organization{
			Model: model.Model{
				ID:        result.OrganizationID,
				CreatedAt: result.CreatedAt,
				UpdatedAt: result.UpdatedAt,
			},
			Name:        result.OrganizationName,
			ImageUrl:    result.OrganizationImageUrl,
			Description: result.OrganizationDescription,
			MemberCount: result.OrganizationMemberCount,
		}

		var roles []*model.OrganizationRole
		if result.RolesJSON != "" && result.RolesJSON != "[]" {
			if err := json.Unmarshal([]byte(result.RolesJSON), &roles); err == nil {
				memberships[i].Roles = roles
			}
		}
	}

	return handler.SendSuccess(c, memberships)
}

func (h *Handler) GetUserWorkspaceMemberships(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	var queryResults []WorkspaceMembershipQueryResult
	rawSQL := `
		SELECT
			workspace_memberships.id,
			workspace_memberships.created_at,
			workspace_memberships.updated_at,
			workspace_memberships.workspace_id,
			workspace_memberships.organization_id,
			workspace_memberships.organization_membership_id,
			workspace_memberships.user_id,
			workspaces.name as workspace_name,
			workspaces.image_url as workspace_image_url,
			workspaces.description as workspace_description,
			workspaces.member_count as workspace_member_count,
			organizations.name as organization_name,
			organizations.image_url as organization_image_url,
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', workspace_roles.id,
						'name', workspace_roles.name,
						'permissions', workspace_roles.permissions,
						'organization_id', workspace_roles.organization_id,
						'deployment_id', workspace_roles.deployment_id,
						'workspace_id', workspace_roles.workspace_id,
						'created_at', workspace_roles.created_at,
						'updated_at', workspace_roles.updated_at
					) ORDER BY workspace_roles.name
				)
				FROM workspace_membership_roles
				JOIN workspace_roles ON workspace_membership_roles.workspace_role_id = workspace_roles.id
				WHERE workspace_membership_roles.workspace_membership_id = workspace_memberships.id
				), '[]'::json
			) as roles_json
		FROM workspace_memberships
		JOIN workspaces ON workspace_memberships.workspace_id = workspaces.id
		JOIN organizations ON workspace_memberships.organization_id = organizations.id
		WHERE workspace_memberships.user_id = ?
			AND workspace_memberships.deleted_at IS NULL
			AND workspaces.deleted_at IS NULL
			AND organizations.deleted_at IS NULL
	`

	args := []interface{}{session.ActiveSignin.UserID}
	orgID := c.Query("org_id")
	if orgID != "" {
		rawSQL += " AND workspace_memberships.organization_id = ?"
		args = append(args, orgID)
	}

	rawSQL += " ORDER BY workspace_memberships.created_at DESC"

	if err := database.Connection.Clauses(dbresolver.Read).Raw(rawSQL, args...).Scan(&queryResults).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to get user workspace memberships")
	}

	memberships := make([]model.WorkspaceMembership, len(queryResults))
	for i, result := range queryResults {
		memberships[i] = result.WorkspaceMembership
		memberships[i].Workspace = model.Workspace{
			Model: model.Model{
				ID:        result.WorkspaceID,
				CreatedAt: result.CreatedAt,
				UpdatedAt: result.UpdatedAt,
			},
			Name:        result.WorkspaceName,
			ImageUrl:    result.WorkspaceImageUrl,
			Description: result.WorkspaceDescription,
			MemberCount: result.WorkspaceMemberCount,
		}
		memberships[i].Organization = model.Organization{
			Model: model.Model{
				ID: result.OrganizationID,
			},
			Name:     result.OrganizationName,
			ImageUrl: result.OrganizationImageUrl,
		}

		var roles []*model.WorkspaceRole
		if result.RolesJSON != "" && result.RolesJSON != "[]" {
			if err := json.Unmarshal([]byte(result.RolesJSON), &roles); err == nil {
				memberships[i].Roles = roles
			}
		}
	}

	return handler.SendSuccess(c, memberships)
}

func (h *Handler) MakeEmailPrimary(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	emailID := c.Params("id")
	if emailID == "" {
		return handler.SendBadRequest(c, nil, "Email address ID is required")
	}

	var emailAddress model.UserEmailAddress
	if err := database.Connection.Where("id = ? AND user_id = ? AND verified = ?", emailID, session.ActiveSignin.UserID, true).First(&emailAddress).Error; err != nil {
		return handler.SendBadRequest(c, nil, "Email address not found or not verified")
	}

	if err := database.Connection.Model(&model.User{}).Where("id = ?", session.ActiveSignin.UserID).Update("primary_email_address_id", emailID).Error; err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to update primary email", handler.ErrInternal)
	}

	return handler.SendSuccess(c, "Primary email updated successfully")
}

func (h *Handler) MakePhonePrimary(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	phoneID := c.Params("id")
	if phoneID == "" {
		return handler.SendBadRequest(c, nil, "Phone number ID is required")
	}

	var phoneNumber model.UserPhoneNumber
	if err := database.Connection.Where("id = ? AND user_id = ? AND verified = ?", phoneID, session.ActiveSignin.UserID, true).First(&phoneNumber).Error; err != nil {
		return handler.SendBadRequest(c, nil, "Phone number not found or not verified")
	}

	if err := database.Connection.Model(&model.User{}).Where("id = ?", session.ActiveSignin.UserID).Update("primary_phone_number_id", phoneID).Error; err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to update primary phone", handler.ErrInternal)
	}

	return handler.SendSuccess(c, "Primary phone updated successfully")
}

func (h *Handler) UpdatePassword(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	b, validation := handler.Validate[UpdatePasswordSchema](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	var user model.User
	if err := database.Connection.Clauses(dbresolver.Read).Select("*").First(&user, session.ActiveSignin.UserID).Error; err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to load user")
	}

	// If user has a password set, verify the current password
	if user.Password != "" {
		isValid, err := utils.ComparePassword(user.Password, b.CurrentPassword)
		if err != nil || !isValid {
			return handler.SendBadRequest(c, nil, "Current password is incorrect")
		}
	}

	if len(b.NewPassword) < 6 || len(b.NewPassword) > 125 {
		return handler.SendBadRequest(c, nil, "Password must be 6-125 characters long")
	}

	hashedPassword, err := utils.HashPassword(b.NewPassword)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to hash password")
	}

	if err := database.Connection.Model(&user).Update("password", hashedPassword).Error; err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to update password")
	}

	return handler.SendSuccess(c, "Password updated successfully")
}

func (h *Handler) RemovePassword(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	b, validation := handler.Validate[RemovePasswordSchema](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	var user model.User
	if err := database.Connection.Preload("UserEmailAddresses").
		Preload("UserPhoneNumbers").
		Preload("SocialConnections").
		Preload("UserAuthenticator").
		First(&user, session.ActiveSignin.UserID).Error; err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to load user")
	}

	deployment := handler.GetDeployment(c)

	isValid, err := utils.ComparePassword(user.Password, b.CurrentPassword)
	if err != nil || !isValid {
		return handler.SendBadRequest(c, nil, "Current password is incorrect")
	}

	if err := h.service.ValidatePasswordRemoval(&user, &deployment); err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	if err := database.Connection.Model(&user).Update("password", "").Error; err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to remove password")
	}

	return handler.SendSuccess(c, "Password removed successfully")
}

func (h *Handler) DeleteAccount(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	b, validation := handler.Validate[DeleteAccountSchema](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	var user model.User
	if err := database.Connection.First(&user, session.ActiveSignin.UserID).Error; err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to load user")
	}

	isValid, err := utils.ComparePassword(user.Password, b.Password)
	if err != nil || !isValid {
		return handler.SendBadRequest(c, nil, "Password is incorrect")
	}

	tx := database.Connection.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	if err := tx.Where("user_id = ?", user.ID).Delete(&model.Signin{}).Error; err != nil {
		tx.Rollback()
		return handler.SendInternalServerError(c, nil, "Failed to delete user sessions")
	}

	if err := tx.Delete(&user).Error; err != nil {
		tx.Rollback()
		return handler.SendInternalServerError(c, nil, "Failed to delete account")
	}

	if err := tx.Commit().Error; err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to complete account deletion")
	}

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess(c, "Account deleted successfully")
}

func (h *Handler) DisconnectSocialConnection(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	connectionID := c.Params("id")
	if connectionID == "" {
		return handler.SendBadRequest(c, nil, "Social connection ID is required")
	}

	query := database.Connection.Where("id = ? AND user_id = ?", connectionID, session.ActiveSignin.UserID).
		Delete(&model.SocialConnection{})
	if query.Error != nil {
		return handler.SendInternalServerError(c, nil, "Failed to disconnect social connection", handler.ErrInternal)
	}

	if query.RowsAffected == 0 {
		return handler.SendBadRequest(c, nil, "Social connection not found")
	}

	return handler.SendSuccess(c, "Social connection disconnected successfully")
}
