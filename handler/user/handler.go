package user

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lib/pq"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/model"
	"github.com/wacht-platform/frontend-api/pkg/idgen"
	"github.com/wacht-platform/frontend-api/utils"
	"gorm.io/datatypes"
	"gorm.io/gorm"
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

func (h *Handler) GetUser(c fiber.Ctx) error {
	session := handler.GetSession(c)

	if session == nil || session.ActiveSignin == nil || session.ActiveSignin.User == nil {
		return handler.SendUnauthorized(
			c,
			nil,
			"Unauthorized",
		)
	}

	return handler.SendSuccess(c, session.ActiveSignin.User)
}

type segmentJSON struct {
	ID           string `json:"id"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
	DeploymentID string `json:"deployment_id"`
	Name         string `json:"name"`
	Type         string `json:"type"`
}

func parseSegmentsJSON(jsonStr string) []*model.Segment {
	if jsonStr == "" || jsonStr == "[]" || jsonStr == "null" {
		return []*model.Segment{}
	}

	var jsonSegments []segmentJSON
	if err := json.Unmarshal([]byte(jsonStr), &jsonSegments); err != nil {
		log.Printf("Error parsing segments JSON: %v, JSON: %s", err, jsonStr)
		return []*model.Segment{}
	}

	var segments []*model.Segment
	for _, jsonSeg := range jsonSegments {
		id, err := strconv.ParseUint(jsonSeg.ID, 10, 64)
		if err != nil {
			continue
		}
		deploymentID, _ := strconv.ParseUint(jsonSeg.DeploymentID, 10, 64)
		createdAt, _ := time.Parse(time.RFC3339, jsonSeg.CreatedAt)
		updatedAt, _ := time.Parse(time.RFC3339, jsonSeg.UpdatedAt)

		segments = append(segments, &model.Segment{
			Model: model.Model{
				ID:        id,
				CreatedAt: createdAt,
				UpdatedAt: updatedAt,
			},
			DeploymentID: deploymentID,
			Name:         jsonSeg.Name,
			Type:         model.SegmentType(jsonSeg.Type),
		})
	}
	return segments
}

func (h *Handler) UpdateUser(c fiber.Ctx) error {
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

	// Handle profile picture removal
	if b.RemoveProfilePicture {
		updates["profile_picture_url"] = ""
		updates["has_profile_picture"] = false
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

	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(deployment.ID, "user.updated", *session.ActiveSignin.UserID, "user")

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	database.SyncUserWrapper(database.Connection, *session.ActiveSignin.UserID, "user.updated")

	return handler.SendSuccess(c, "Profile updated successfully")
}

func (h *Handler) GetUserEmailAddresses(c fiber.Ctx) error {
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

func (h *Handler) GetUserEmailAddress(c fiber.Ctx) error {
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

func (h *Handler) DeleteUserEmailAddress(c fiber.Ctx) error {
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

	emailIDUint, _ := strconv.ParseUint(emailID, 10, 64)
	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(deployment.ID, "user.email.removed", emailIDUint, "user_email")

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

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	database.SyncUserWrapper(database.Connection, *session.ActiveSignin.UserID, "user.email.removed")

	return handler.SendSuccess(c, "Deleted successfully")
}

func (h *Handler) CreateUserEmailAddress(c fiber.Ctx) error {
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

	if h.service.CheckEmailExists(b.Email, deployment.ID) {
		return handler.SendBadRequest(c, nil, "Email address already exists")
	}

	newEmail := model.UserEmailAddress{
		Model: model.Model{
			ID: idgen.NextID(),
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

	utils.PublishWebhookEvent(deployment.ID, "user.email.added", newEmail.ID, "user_email")

	database.SyncUserWrapper(database.Connection, *session.ActiveSignin.UserID, "user.email.added")

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess(c, newEmail)
}

func (h *Handler) AttemptEmailVerification(c fiber.Ctx) error {
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

	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(deployment.ID, "user.email.verified", emailAddress.ID, "user_email")

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess(c, "Email verified successfully")
}

func (h *Handler) PrepareEmailVerification(c fiber.Ctx) error {
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
		c.IP(),
		c.Get("User-Agent"),
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

func (h *Handler) GetUserPhoneNumbers(c fiber.Ctx) error {
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

func (h *Handler) GetPhoneNumber(c fiber.Ctx) error {
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

func (h *Handler) AddPhoneNumber(c fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	b, validation := handler.Validate[AddUserPhoneNumberSchema](c)

	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	deployment := handler.GetDeployment(c)

	if err := h.service.ValidatePhoneRestrictions(b.PhoneNumber, b.CountryCode, deployment.Restrictions); err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	if h.service.CheckUserphoneExists(b.PhoneNumber, b.CountryCode, deployment.ID) {
		return handler.SendBadRequest(c, nil, "Phone number already exists")
	}

	phoneNumber := model.UserPhoneNumber{
		Model: model.Model{
			ID: idgen.NextID(),
		},
		PhoneNumber:  b.PhoneNumber,
		CountryCode:  b.CountryCode,
		DeploymentID: deployment.ID,
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

	utils.PublishWebhookEvent(deployment.ID, "user.phone.added", phoneNumber.ID, "user_phone")

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess(c, phoneNumber)
}

func (h *Handler) PreparePhoneVerification(c fiber.Ctx) error {
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

	err := h.service.sendSmsOTPVerification(
		deployment.ID,
		*session.ActiveSignin.UserID,
		phoneNumber.PhoneNumber,
		phoneNumber.CountryCode,
		c.IP(),
		c.Get("User-Agent"),
	)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to send SMS",
			handler.ErrInternal,
		)
	}

	return handler.SendSuccess(c, "Verification code sent successfully")
}

func (h *Handler) AttemptPhoneVerification(c fiber.Ctx) error {
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

	code := c.FormValue("code")
	if code == "" {
		return handler.SendBadRequest(c, nil, "OTP code is required")
	}

	isValid, err := h.service.verifyPhoneOTP(
		phoneNumber.PhoneNumber,
		phoneNumber.CountryCode,
		code,
	)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to verify OTP",
			handler.ErrInternal,
		)
	}

	if !isValid {
		return handler.SendBadRequest(c, nil, "Invalid OTP code")
	}

	phoneNumber.Verified = true
	phoneNumber.CanUseForSecondFactor = true
	phoneNumber.VerifiedAt = time.Now().UTC()
	if err = database.Connection.Save(&phoneNumber).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	utils.PublishWebhookEvent(deployment.ID, "user.phone.verified", phoneNumber.ID, "user_phone")

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess(c, "Phone number verified successfully")
}

func (h *Handler) DeletePhoneNumber(c fiber.Ctx) error {
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

	phoneIDUint, _ := strconv.ParseUint(phoneID, 10, 64)
	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(deployment.ID, "user.phone.removed", phoneIDUint, "user_phone")

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

	if query.RowsAffected == 0 {
		return handler.SendBadRequest(c, nil, "Phone number not found")
	}

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess(c, "Deleted successfully")
}

func (h *Handler) GenerateAuthenticator(c fiber.Ctx) error {
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

	plaintextSecret := key.Secret()
	encryptedSecret, err := utils.EncryptAtRest(plaintextSecret)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to encrypt authenticator secret",
			handler.ErrInternal,
		)
	}

	authenticator := &model.UserAuthenticator{
		Model: model.Model{
			ID: idgen.NextID(),
		},
		TotpSecret: encryptedSecret,
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

	// Return the plaintext base32 secret — this is the user's only chance to
	// see it for QR-code scanning. The DB row stores only the ciphertext.
	resp := map[string]any{
		"id":          strconv.Itoa(int(authenticator.ID)),
		"otp_url":     authenticator.OtpUrl,
		"totp_secret": plaintextSecret,
		"created_at":  authenticator.CreatedAt,
	}

	return handler.SendSuccess(c, resp)
}

func (h *Handler) VerifyAuthenticator(c fiber.Ctx) error {
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

	plaintextSecret, err := utils.DecryptAtRest(authenticator.TotpSecret)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to decrypt authenticator secret",
			handler.ErrInternal,
		)
	}

	valid, err := totp.ValidateCustom(
		firstCode,
		plaintextSecret,
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
		plaintextSecret,
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

	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(deployment.ID, "user.mfa.enabled", *session.ActiveSignin.UserID, "user_authenticator")

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess(c, authenticator)
}

func (h *Handler) DeleteAuthenticator(c fiber.Ctx) error {
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

	deployment := handler.GetDeployment(c)

	tx := database.Connection.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	query := tx.Where("id = ? AND user_id = ?", authenticatorID, session.ActiveSignin.UserID).
		Delete(&model.UserAuthenticator{})
	if query.Error != nil {
		tx.Rollback()
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to delete authenticator",
			handler.ErrInternal,
		)
	}

	if query.RowsAffected == 0 {
		tx.Rollback()
		return handler.SendBadRequest(c, nil, "Authenticator not found")
	}

	if err := tx.Model(&model.User{}).Where("id = ?", session.ActiveSignin.UserID).Updates(map[string]interface{}{
		"backup_codes":           pq.Array([]string{}),
		"backup_codes_generated": false,
		"second_factor_policy":   deployment.AuthSettings.SecondFactorPolicy,
	}).Error; err != nil {
		tx.Rollback()
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to clear backup codes and reset settings",
			handler.ErrInternal,
		)
	}

	if err := tx.Commit().Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to commit transaction",
			handler.ErrInternal,
		)
	}

	utils.PublishWebhookEvent(deployment.ID, "user.mfa.disabled", *session.ActiveSignin.UserID, "user_authenticator")
	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess(c, "Authenticator deleted successfully")
}

func (h *Handler) GenerateBackupCodes(c fiber.Ctx) error {
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

	hashedCodes, err := hashBackupCodes(backupCodes)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to hash backup codes",
			handler.ErrInternal,
		)
	}

	if err := database.Connection.Model(&model.User{}).Where("id = ?", session.ActiveSignin.UserID).Updates(map[string]interface{}{
		"backup_codes":           pq.Array(hashedCodes),
		"backup_codes_generated": true,
	}).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to save backup codes",
			handler.ErrInternal,
		)
	}

	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(deployment.ID, "user.backup_codes.generated", *session.ActiveSignin.UserID, "user")

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	// Return the plaintext codes — this is the user's only chance to see them.
	return handler.SendSuccess(c, backupCodes)
}

// hashBackupCodes hashes each plaintext code with argon2. The plaintext list is
// returned to the user one time; the hashes are what live in the DB.
func hashBackupCodes(codes []string) ([]string, error) {
	hashed := make([]string, len(codes))
	for i, code := range codes {
		h, err := utils.HashPassword(code)
		if err != nil {
			return nil, err
		}
		hashed[i] = h
	}
	return hashed, nil
}

func (h *Handler) RegenerateBackupCodes(c fiber.Ctx) error {
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

	hashedCodes, err := hashBackupCodes(backupCodes)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to hash regenerated backup codes",
			handler.ErrInternal,
		)
	}

	if err := database.Connection.Model(&model.User{}).Where("id = ?", session.ActiveSignin.UserID).Updates(map[string]interface{}{
		"backup_codes":           pq.Array(hashedCodes),
		"backup_codes_generated": true,
	}).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to save regenerated backup codes",
			handler.ErrInternal,
		)
	}

	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(deployment.ID, "user.backup_codes.regenerated", *session.ActiveSignin.UserID, "user")

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	// Return the plaintext codes — this is the user's only chance to see them.
	return handler.SendSuccess(c, backupCodes)
}

func (h *Handler) GetUserSignins(c fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	var signins []model.Signin

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

func (h *Handler) UploadProfilePicture(c fiber.Ctx) error {
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
		log.Println(err)
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to upload profile picture",
			handler.ErrInternal,
		)
	}

	if err := database.Connection.Model(&model.User{}).Where("id = ?", session.ActiveSignin.UserID).Updates(map[string]any{
		"profile_picture_url": url,
		"has_profile_picture": true,
	}).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to save user",
		)
	}

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess[any](c, nil)
}

func (h *Handler) SignOutFromSession(c fiber.Ctx) error {
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

	isCurrentSignin := session.ActiveSignin != nil && session.ActiveSignin.ID == signin.ID

	if err := database.Connection.Delete(&signin).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to sign out from session",
			handler.ErrInternal,
		)
	}

	if isCurrentSignin {
		database.Connection.Model(&model.Session{}).Where("id = ?", session.ID).Update("active_signin_id", nil)
	}

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess[any](c, nil)
}

func (h *Handler) GetUserOrganizationMemberships(c fiber.Ctx) error {
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
			organization_memberships.public_metadata as membership_public_metadata,
			organizations.name as organization_name,
			organizations.image_url as organization_image_url,
			organizations.description as organization_description,
			organizations.member_count as organization_member_count,
			organizations.whitelisted_ips as organization_whitelisted_ips,
			organizations.auto_assigned_workspace_id as organization_auto_assigned_workspace_id,
			organizations.enforce_mfa_setup as organization_enforce_mfa,
			organizations.enable_ip_restriction as organization_enable_ip_restriction,
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', organization_roles.id::text,
						'organization_id', organization_roles.organization_id::text,
						'name', organization_roles.name,
						'permissions', organization_roles.permissions,
						'deployment_id', organization_roles.deployment_id::text,
						'created_at', organization_roles.created_at,
						'updated_at', organization_roles.updated_at
					) ORDER BY organization_roles.name
				)
				FROM organization_membership_roles
				JOIN organization_roles ON organization_membership_roles.organization_role_id = organization_roles.id
				WHERE organization_membership_roles.organization_membership_id = organization_memberships.id
				), '[]'::json
			) as roles_json,
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', s.id::text,
						'created_at', s.created_at,
						'updated_at', s.updated_at,
						'deployment_id', s.deployment_id::text,
						'name', s.name,
						'type', s.type
					)
				)
				FROM organization_segments os
				JOIN segments s ON os.segment_id = s.id
				WHERE os.organization_id = organizations.id AND s.deleted_at IS NULL
				), '[]'::json
			) as segments_json
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

		var whitelistedIPs []string
		if result.OrganizationWhitelistedIPs != "" && result.OrganizationWhitelistedIPs != "{}" {
			trimmed := strings.Trim(result.OrganizationWhitelistedIPs, "{}")
			if trimmed != "" {
				whitelistedIPs = strings.Split(trimmed, ",")
			}
		}

		memberships[i].Organization = &model.PublicOrganizationData{
			Model: model.Model{
				ID:        result.OrganizationID,
				CreatedAt: result.CreatedAt,
				UpdatedAt: result.UpdatedAt,
			},
			Name:                    result.OrganizationName,
			ImageUrl:                result.OrganizationImageUrl,
			Description:             result.OrganizationDescription,
			MemberCount:             result.OrganizationMemberCount,
			WhitelistedIPs:          whitelistedIPs,
			AutoAssignedWorkspaceID: result.OrganizationAutoAssignedWorkspaceID,
			EnforceMFASetup:         result.OrganizationEnforceMFASetup,
			EnableIPRestriction:     result.OrganizationEnableIPRestriction,
		}

		if result.MembershipPublicMetadata != "" && result.MembershipPublicMetadata != "null" {
			var metadata datatypes.JSONMap
			if err := json.Unmarshal([]byte(result.MembershipPublicMetadata), &metadata); err != nil {
				memberships[i].PublicMetadata = make(datatypes.JSONMap)
			} else {
				memberships[i].PublicMetadata = metadata
			}
		} else {
			memberships[i].PublicMetadata = make(datatypes.JSONMap)
		}

		memberships[i].Organization.Segments = parseSegmentsJSON(result.SegmentsJSON)

		var roles []*model.OrganizationRole
		err := json.Unmarshal([]byte(result.RolesJSON), &roles)
		if err == nil {
			memberships[i].Roles = roles
		}
	}

	deployment := handler.GetDeployment(c)
	clientIP := c.IP()

	user := session.ActiveSignin.User

	for i := range memberships {
		eligibility := utils.CalculateOrganizationEligibility(
			user,
			memberships[i].Organization,
			memberships[i].Roles,
			clientIP,
			&deployment,
		)
		memberships[i].EligibilityRestriction = eligibility
	}

	return handler.SendSuccess(c, memberships)
}

func (h *Handler) GetUserWorkspaceMemberships(c fiber.Ctx) error {
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
			workspace_memberships.public_metadata as membership_public_metadata,
			workspaces.name as workspace_name,
			workspaces.image_url as workspace_image_url,
			workspaces.description as workspace_description,
			workspaces.member_count as workspace_member_count,
			workspaces.whitelisted_ips as workspace_whitelisted_ips,
			workspaces.enforce_mfa_setup as workspace_enforce_mfa,
			workspaces.enable_ip_restriction as workspace_enable_ip_restriction,
			organizations.name as organization_name,
			organizations.image_url as organization_image_url,
			organizations.description as organization_description,
			organizations.member_count as organization_member_count,
			organizations.whitelisted_ips as organization_whitelisted_ips,
			organizations.auto_assigned_workspace_id as organization_auto_assigned_workspace_id,
			organizations.enforce_mfa_setup as organization_enforce_mfa,
			organizations.enable_ip_restriction as organization_enable_ip_restriction,
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', workspace_roles.id::text,
						'name', workspace_roles.name,
						'permissions', workspace_roles.permissions,
						'organization_id', workspace_roles.organization_id::text,
						'deployment_id', workspace_roles.deployment_id::text,
						'workspace_id', workspace_roles.workspace_id::text,
						'created_at', workspace_roles.created_at,
						'updated_at', workspace_roles.updated_at
					) ORDER BY workspace_roles.name
				)
				FROM workspace_membership_roles
				JOIN workspace_roles ON workspace_membership_roles.workspace_role_id = workspace_roles.id
				WHERE workspace_membership_roles.workspace_membership_id = workspace_memberships.id
				), '[]'::json
			) as roles_json,
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', s.id::text,
						'created_at', s.created_at,
						'updated_at', s.updated_at,
						'deployment_id', s.deployment_id::text,
						'name', s.name,
						'type', s.type
					)
				)
				FROM workspace_segments ws
				JOIN segments s ON ws.segment_id = s.id
				WHERE ws.workspace_id = workspaces.id AND s.deleted_at IS NULL
				), '[]'::json
			) as segments_json,
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', organization_roles.id::text,
						'organization_id', organization_roles.organization_id::text,
						'name', organization_roles.name,
						'permissions', organization_roles.permissions,
						'deployment_id', organization_roles.deployment_id::text,
						'created_at', organization_roles.created_at,
						'updated_at', organization_roles.updated_at
					) ORDER BY organization_roles.name
				)
				FROM organization_membership_roles
				JOIN organization_roles ON organization_membership_roles.organization_role_id = organization_roles.id
				WHERE organization_membership_roles.organization_membership_id = workspace_memberships.organization_membership_id
				), '[]'::json
			) as organization_roles_json
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

		// Parse workspace whitelisted IPs
		var workspaceWhitelistedIPs []string
		if result.WorkspaceWhitelistedIPs != "" && result.WorkspaceWhitelistedIPs != "{}" {
			trimmed := strings.Trim(result.WorkspaceWhitelistedIPs, "{}")
			if trimmed != "" {
				workspaceWhitelistedIPs = strings.Split(trimmed, ",")
			}
		}

		memberships[i].Workspace = &model.PublicWorkspaceData{
			Model: model.Model{
				ID:        result.WorkspaceID,
				CreatedAt: result.CreatedAt,
				UpdatedAt: result.UpdatedAt,
			},
			Name:                result.WorkspaceName,
			ImageUrl:            result.WorkspaceImageUrl,
			Description:         result.WorkspaceDescription,
			MemberCount:         result.WorkspaceMemberCount,
			WhitelistedIPs:      workspaceWhitelistedIPs,
			EnforceMFASetup:     result.WorkspaceEnforceMFASetup,
			EnableIPRestriction: result.WorkspaceEnableIPRestriction,
		}

		// Parse organization whitelisted IPs
		var orgWhitelistedIPs []string
		if result.OrganizationWhitelistedIPs != "" && result.OrganizationWhitelistedIPs != "{}" {
			trimmed := strings.Trim(result.OrganizationWhitelistedIPs, "{}")
			if trimmed != "" {
				orgWhitelistedIPs = strings.Split(trimmed, ",")
			}
		}

		memberships[i].Organization = &model.PublicOrganizationData{
			Model: model.Model{
				ID: result.OrganizationID,
			},
			Name:                    result.OrganizationName,
			ImageUrl:                result.OrganizationImageUrl,
			Description:             result.OrganizationDescription,
			MemberCount:             result.OrganizationMemberCount,
			WhitelistedIPs:          orgWhitelistedIPs,
			AutoAssignedWorkspaceID: result.OrganizationAutoAssignedWorkspaceID,
			EnforceMFASetup:         result.OrganizationEnforceMFASetup,
			EnableIPRestriction:     result.OrganizationEnableIPRestriction,
		}

		// Parse public metadata
		if result.MembershipPublicMetadata != "" && result.MembershipPublicMetadata != "null" {
			var metadata datatypes.JSONMap
			if err := json.Unmarshal([]byte(result.MembershipPublicMetadata), &metadata); err != nil {
				memberships[i].PublicMetadata = make(datatypes.JSONMap)
			} else {
				memberships[i].PublicMetadata = metadata
			}
		} else {
			memberships[i].PublicMetadata = make(datatypes.JSONMap)
		}

		memberships[i].Workspace.Segments = parseSegmentsJSON(result.SegmentsJSON)

		var roles []*model.WorkspaceRole
		err := json.Unmarshal([]byte(result.RolesJSON), &roles)
		if err == nil {
			memberships[i].Roles = roles
		}

		var orgRoles []*model.OrganizationRole
		err = json.Unmarshal([]byte(result.OrganizationRolesJSON), &orgRoles)
		if err == nil {
			if memberships[i].OrganizationMembership == nil {
				memberships[i].OrganizationMembership = &model.OrganizationMembership{}
			}
			memberships[i].OrganizationMembership.Roles = orgRoles
		}
	}

	user := session.ActiveSignin.User
	deployment := handler.GetDeployment(c)
	clientIP := c.IP()

	for i := range memberships {
		eligibility := utils.CalculateWorkspaceEligibility(
			user,
			memberships[i].Workspace,
			memberships[i].Roles,
			memberships[i].OrganizationMembership.Roles,
			clientIP,
			&deployment,
		)
		memberships[i].EligibilityRestriction = eligibility
	}

	return handler.SendSuccess(c, memberships)
}

func (h *Handler) MakeEmailPrimary(c fiber.Ctx) error {
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

	var user model.User
	if err := database.Connection.Preload("UserEmailAddresses").First(&user, session.ActiveSignin.UserID).Error; err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to load user")
	}

	var oldPrimaryEmail string
	if user.PrimaryEmailAddressID != nil {
		for _, email := range user.UserEmailAddresses {
			if email.ID == *user.PrimaryEmailAddressID {
				oldPrimaryEmail = email.EmailAddress
				break
			}
		}
	}

	if err := database.Connection.Model(&model.User{}).Where("id = ?", session.ActiveSignin.UserID).Update("primary_email_address_id", emailID).Error; err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to update primary email", handler.ErrInternal)
	}

	deployment := handler.GetDeployment(c)
	if oldPrimaryEmail != "" && oldPrimaryEmail != emailAddress.EmailAddress {
		_ = h.service.nats.SendPrimaryEmailChangeEmail(
			deployment.ID,
			user.ID,
			oldPrimaryEmail,
			oldPrimaryEmail,
			emailAddress.EmailAddress,
		)
		_ = h.service.nats.SendPrimaryEmailChangeEmail(
			deployment.ID,
			user.ID,
			emailAddress.EmailAddress,
			oldPrimaryEmail,
			emailAddress.EmailAddress,
		)
	}

	utils.PublishWebhookEvent(deployment.ID, "user.email.primary.changed", user.ID, "user")

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess(c, "Primary email updated successfully")
}

func (h *Handler) MakePhonePrimary(c fiber.Ctx) error {
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

	var user model.User
	if err := database.Connection.First(&user, session.ActiveSignin.UserID).Error; err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to load user")
	}

	if err := database.Connection.Model(&model.User{}).Where("id = ?", session.ActiveSignin.UserID).Update("primary_phone_number_id", phoneID).Error; err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to update primary phone", handler.ErrInternal)
	}

	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(deployment.ID, "user.phone.primary.changed", user.ID, "user")

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess(c, "Primary phone updated successfully")
}

func (h *Handler) UpdatePassword(c fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	b, validation := handler.Validate[UpdatePasswordSchema](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	var user model.User
	if err := database.Connection.Preload("UserEmailAddresses").Clauses(dbresolver.Read).Select("*").First(&user, session.ActiveSignin.UserID).Error; err != nil {
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

	deployment := handler.GetDeployment(c)
	if user.PrimaryEmailAddressID != nil {
		for _, email := range user.UserEmailAddresses {
			if email.ID == *user.PrimaryEmailAddressID {
				_ = h.service.nats.SendPasswordChangeEmail(deployment.ID, user.ID, email.EmailAddress)
				break
			}
		}
	}

	utils.PublishWebhookEvent(deployment.ID, "user.password.updated", user.ID, "user")

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess(c, "Password updated successfully")
}

func (h *Handler) RemovePassword(c fiber.Ctx) error {
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

	deploymentID := deployment.ID
	if user.PrimaryEmailAddressID != nil {
		for _, email := range user.UserEmailAddresses {
			if email.ID == *user.PrimaryEmailAddressID {
				_ = h.service.nats.SendPasswordRemoveEmail(deploymentID, user.ID, email.EmailAddress)
				break
			}
		}
	}

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess(c, "Password removed successfully")
}

func (h *Handler) DeleteAccount(c fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	var user model.User
	if err := database.Connection.First(&user, session.ActiveSignin.UserID).Error; err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to load user")
	}

	tx := database.Connection.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Consolidate all deletions into a single roundtrip
	deleteQuery := `
		DELETE FROM social_connections WHERE user_id = $1;
		DELETE FROM user_email_addresses WHERE user_id = $1;
		DELETE FROM user_phone_numbers WHERE user_id = $1;
		DELETE FROM user_segments WHERE user_id = $1;
		DELETE FROM user_authenticators WHERE user_id = $1;
		DELETE FROM user_passkeys WHERE user_id = $1;
		DELETE FROM notifications WHERE user_id = $1;
		DELETE FROM scim_external_ids WHERE user_id = $1;
		DELETE FROM scim_group_members WHERE user_id = $1;
		DELETE FROM workspace_membership_roles WHERE workspace_membership_id IN (SELECT id FROM workspace_memberships WHERE user_id = $1);
		DELETE FROM workspace_memberships WHERE user_id = $1;
		DELETE FROM organization_membership_roles WHERE organization_membership_id IN (SELECT id FROM organization_memberships WHERE user_id = $1);
		DELETE FROM organization_memberships WHERE user_id = $1;
		DELETE FROM signins WHERE user_id = $1;
		DELETE FROM users WHERE id = $1;
	`
	if err := tx.Exec(deleteQuery, user.ID).Error; err != nil {
		tx.Rollback()
		return handler.SendInternalServerError(c, nil, "Failed to hard delete account")
	}

	deployment := handler.GetDeployment(c)
	utils.PublishWebhookEvent(deployment.ID, "user.deleted", user.ID, "user")

	if err := tx.Commit().Error; err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to complete account deletion")
	}

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess(c, "Account deleted successfully")
}

func (h *Handler) DisconnectSocialConnection(c fiber.Ctx) error {
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

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess(c, "Social connection disconnected successfully")
}

func (h *Handler) InitConnectSocial(c fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	provider := c.Query("provider")
	if provider == "" {
		return handler.SendBadRequest(
			c,
			nil,
			"provider is required",
			handler.ErrProviderRequired,
		)
	}

	deployment := handler.GetDeployment(c)
	customRedirectURI := c.Query("redirect_uri")
	if err := utils.ValidateCustomOAuthRedirectURIForDeployment(&deployment, customRedirectURI); err != nil {
		return handler.SendBadRequest(
			c,
			nil,
			err.Error(),
		)
	}

	var keypair model.DeploymentKeyPair
	if err := database.Connection.Where("deployment_id = ?", deployment.ID).
		First(&keypair).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to get deployment keypair",
		)
	}

	finalRedirectURI := customRedirectURI
	if finalRedirectURI == "" {
		if deployment.UISettings.AfterSigninRedirectURL != "" {
			finalRedirectURI = deployment.UISettings.AfterSigninRedirectURL
		} else {
			finalRedirectURI = fmt.Sprintf("https://%s", deployment.FrontendHost)
		}
	}

	secret := utils.GetOAuthStateSecret(deployment.ID, keypair.PrivateKey)
	stateData := utils.OAuthStateData{
		Action:       "connect_social",
		UserID:       session.ActiveSignin.UserID,
		SessionID:    &session.ID,
		Provider:     provider,
		RedirectURI:  finalRedirectURI,
		FrontendHost: deployment.FrontendHost,
	}
	stateToken, err := utils.GenerateOAuthState(stateData, secret)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to generate state token",
		)
	}

	url, err := utils.GenerateOAuthConnectURL(provider, stateToken, &deployment)
	if err != nil {
		return handler.SendBadRequest(
			c,
			nil,
			err.Error(),
			handler.ErrProviderNotConfigured,
		)
	}

	return handler.SendSuccess(c, fiber.Map{
		"oauth_url": url,
	})
}

func (h *Handler) ConnectSocialCallback(c fiber.Ctx) error {
	code := c.Query("code")
	deployment := handler.GetDeployment(c)
	session := handler.GetSession(c)

	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	if code == "" {
		return handler.SendBadRequest(
			c,
			nil,
			"code is not present in uri",
			handler.ErrCodeRequired,
		)
	}

	stateToken := c.Query("state")
	if stateToken == "" {
		return handler.SendBadRequest(
			c,
			nil,
			"State parameter is missing",
			handler.ErrInvalidState,
		)
	}

	var keypair model.DeploymentKeyPair
	if err := database.Connection.Where("deployment_id = ?", deployment.ID).
		First(&keypair).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to get deployment keypair",
		)
	}

	secret := utils.GetOAuthStateSecret(deployment.ID, keypair.PrivateKey)
	stateData, err := utils.ValidateOAuthState(stateToken, secret, 10*time.Minute)
	if err != nil {
		return handler.SendBadRequest(
			c,
			nil,
			fmt.Sprintf("Invalid or expired state: %v", err),
			handler.ErrInvalidState,
		)
	}

	if stateData.Action != "connect_social" {
		return handler.SendBadRequest(
			c,
			nil,
			"Invalid state action for connect social",
			handler.ErrInvalidState,
		)
	}

	if stateData.UserID == nil || *stateData.UserID != *session.ActiveSignin.UserID {
		return handler.SendBadRequest(
			c,
			nil,
			"Please sign in with the correct account to add this connection",
			handler.ErrInvalidState,
		)
	}

	if stateData.SessionID == nil || *stateData.SessionID != session.ID {
		return handler.SendBadRequest(
			c,
			nil,
			"State token session mismatch",
			handler.ErrInvalidState,
		)
	}

	provider := stateData.Provider
	if provider == "" {
		return handler.SendBadRequest(
			c,
			nil,
			"Invalid provider in state",
			handler.ErrInvalidState,
		)
	}

	customRedirectURI := stateData.RedirectURI
	if err := utils.ValidateCustomOAuthRedirectURIForDeployment(&deployment, customRedirectURI); err != nil {
		return handler.SendBadRequest(
			c,
			nil,
			err.Error(),
			handler.ErrInvalidState,
		)
	}

	var ssoProvider model.SocialConnectionProvider
	switch provider {
	case "google_oauth":
		ssoProvider = model.SocialConnectionProviderGoogle
	case "github_oauth":
		ssoProvider = model.SocialConnectionProviderGitHub
	case "microsoft_oauth":
		ssoProvider = model.SocialConnectionProviderMicrosoft
	case "facebook_oauth":
		ssoProvider = model.SocialConnectionProviderFacebook
	case "x_oauth":
		ssoProvider = model.SocialConnectionProviderX
	case "linkedin_oauth":
		ssoProvider = model.SocialConnectionProviderLinkedIn
	case "gitlab_oauth":
		ssoProvider = model.SocialConnectionProviderGitLab
	case "discord_oauth":
		ssoProvider = model.SocialConnectionProviderDiscord
	case "apple_oauth":
		ssoProvider = model.SocialConnectionProviderApple
	default:
		return handler.SendBadRequest(c, nil, "Invalid provider")
	}

	conf, err := utils.GetOAuthConfigForDeployment(ssoProvider, &deployment)
	if err != nil {
		return handler.SendBadRequest(
			c,
			nil,
			err.Error(),
			handler.ErrProviderNotConfigured,
		)
	}

	token, err := conf.Exchange(c.RequestCtx(), code)
	if err != nil || !token.Valid() {
		return handler.SendBadRequest(
			c,
			nil,
			"Authentication state not correct. Please try connecting again",
			handler.ErrCodeRequired,
		)
	}

	oauthUser, err := utils.ExchangeTokenForUser(token, ssoProvider, conf.ClientID)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to get user info from provider",
		)
	}

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		var userEmailAddress model.UserEmailAddress
		err := tx.Where("deployment_id = ? AND email_address = ?",
			deployment.ID, oauthUser.Email).
			First(&userEmailAddress).Error

		if err == gorm.ErrRecordNotFound {
			userEmailAddress = model.UserEmailAddress{
				Model: model.Model{
					ID: idgen.NextID(),
				},
				DeploymentID:         deployment.ID,
				UserID:               session.ActiveSignin.UserID,
				EmailAddress:         oauthUser.Email,
				IsPrimary:            false,
				Verified:             true,
				VerifiedAt:           time.Now(),
				VerificationStrategy: utils.GetVerificationStrategyForProvider(provider),
			}

			if err := tx.Create(&userEmailAddress).Error; err != nil {
				if pgErr, ok := err.(*pgconn.PgError); ok {
					if pgErr.ConstraintName == "idx_deployment_user_email_address_email" {
						return handler.ErrEmailExists
					}
				}
				return err
			}
		} else if err != nil {
			return err
		} else {
			if *userEmailAddress.UserID != *session.ActiveSignin.UserID {
				return handler.ErrEmailExists
			}
		}

		encAccess, err := utils.EncryptAtRest(token.AccessToken)
		if err != nil {
			return err
		}
		encRefresh, err := utils.EncryptAtRest(token.RefreshToken)
		if err != nil {
			return err
		}

		socialConnection := model.SocialConnection{
			UserID:             *session.ActiveSignin.UserID,
			UserEmailAddressID: userEmailAddress.ID,
			Provider:           ssoProvider,
			EmailAddress:       oauthUser.Email,
			FirstName:          oauthUser.FirstName,
			LastName:           oauthUser.LastName,
			AccessToken:        encAccess,
			RefreshToken:       encRefresh,
		}

		if err := tx.Create(&socialConnection).Error; err != nil {
			if pgErr, ok := err.(*pgconn.PgError); ok {
				if strings.Contains(pgErr.ConstraintName, "provider") ||
					strings.Contains(pgErr.ConstraintName, "social") {
					return handler.ErrSocialAccountAlreadyConnected
				}
			}
			return err
		}

		return nil
	})

	if err != nil {
		if err == handler.ErrEmailExists {
			return handler.SendBadRequest(c, nil, "This email address is already associated with another user")
		}
		if err == handler.ErrSocialAccountAlreadyConnected {
			return handler.SendBadRequest(c, nil, "This social account is already connected")
		}
		return handler.SendInternalServerError(c, err, "Failed to connect social account")
	}

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	return handler.SendSuccess(c, fiber.Map{
		"message":      "Social account connected successfully",
		"session":      session,
		"redirect_uri": customRedirectURI,
	})
}
