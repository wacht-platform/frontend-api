package user

import (
	"crypto/rand"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/godruoyi/go-snowflake"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm/clause"
)

type Handler struct {
	service *UserService
}

func NewHandler() *Handler {
	return &Handler{
		service: NewUserService(),
	}
}

func (h *Handler) GetUser(c *fiber.Ctx) error {
	session := handler.GetSession(c)

	err := database.Connection.Preload("ActiveSignin.User").
		Preload("ActiveSignin.User.UserEmailAddresses").
		Preload("ActiveSignin.User.UserPhoneNumbers").
		Preload("ActiveSignin.User.SocialConnections").
		Preload("ActiveSignin.User.UserAuthenticator").
		Where("id = ?", session.ID).
		First(session).Error
	if err != nil {
		log.Println(err)
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	if session.ActiveSignin == nil {
		return handler.SendBadRequest(
			c,
			nil,
			"No active sign-in found",
		)
	}

	return handler.SendSuccess(c, session.ActiveSignin.User)
}

func (h *Handler) UpdateUser(c *fiber.Ctx) error {
	session := handler.GetSession(c)

	b, verr := handler.Validate[UpdateUserSchema](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
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

	return nil
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

	query := database.Connection.Where("id = ? AND user_id = ?", emailID, session.ActiveSignin.UserID).
		Delete(&model.UserEmailAddress{})
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

func (h *Handler) CreateUserEmailAddress(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	b, verr := handler.Validate[AddUserEmailAddressSchema](c)

	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	newEmail := model.UserEmailAddress{
		Model: model.Model{
			ID: uint(snowflake.ID()),
		},
		UserID:   session.ActiveSignin.UserID,
		Email:    b.Email,
		Verified: false,
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

	expectedOTP, err := h.service.GetOTPFromCache(
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

	if err = h.service.RemoveOTPFromCache(strconv.Itoa(int(emailAddress.ID))); err != nil {
		log.Printf("Failed to remove OTP from cache: %v", err)
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

	code, err := totp.GenerateCode(
		session.ActiveSignin.User.OtpSecret,
		time.Now(),
	)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	err = h.service.StoreOTPInCache(
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

	err = h.service.SendEmailOTPVerification(emailAddress.Email, code)
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

	b, verr := handler.Validate[AddUserPhoneNumberSchema](c)

	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
	}

	phoneNumber := model.UserPhoneNumber{
		Model: model.Model{
			ID: uint(snowflake.ID()),
		},
		PhoneNumber: b.PhoneNumber,
	}

	phoneNumber.UserID = session.ActiveSignin.UserID

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

	code, err := totp.GenerateCode(
		session.ActiveSignin.User.OtpSecret,
		time.Now(),
	)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Something went wrong",
			handler.ErrInternal,
		)
	}

	err = h.service.StoreOTPInCache(
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

	err = h.service.SendSmsOTPVerification(phoneNumber.PhoneNumber, code)
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

	expectedOTP, err := h.service.GetOTPFromCache(
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

	if err = h.service.RemoveOTPFromCache(strconv.Itoa(int(phoneNumber.ID))); err != nil {
		log.Printf("Failed to remove OTP from cache: %v", err)
	}

	phoneNumber.Verified = true
	phoneNumber.VerifiedAt = time.Now()
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
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Wacht",
		AccountName: "User",
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
			ID: uint(snowflake.ID()),
		},
		TotpSecret: key.Secret(),
		OtpUrl:     key.URL(),
	}

	if err := database.Connection.Create(authenticator).Error; err != nil {
		log.Println("Failed to save authenticator", err)
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

	b, verr := handler.Validate[VerifyAuthenticatorSchema](c)
	if verr != nil {
		return handler.SendBadRequest(c, verr, "Bad request body")
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

	log.Println("First code", firstCode)
	log.Println("Second code", secondCode)

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
		log.Println("Failed to validate first code", err)
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

	authenticator.UserID = &session.ActiveSignin.UserID
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

	user.BackupCodes = backupCodes
	user.BackupCodesGenerated = true
	if err := database.Connection.Save(&user).Error; err != nil {
		log.Println("Failed to save backup codes", err)
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to save backup codes",
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
	if err := database.Connection.Where("user_id = ? AND expires_at > ?", session.ActiveSignin.UserID, time.Now()).Find(&signins).Error; err != nil {
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

	err = h.service.UploadProfilePicture(session.ActiveSignin.UserID, file)
	if err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to upload profile picture",
			handler.ErrInternal,
		)
	}

	user.ProfilePictureURL = fmt.Sprintf(
		"http://cdn.wacht.tech/%d/%s",
		session.ActiveSignin.UserID,
		file.Filename,
	)
	user.HasProfilePicture = true
	if err := database.Connection.Save(&user).Error; err != nil {
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

	signin.ExpiresAt = time.Now().Format(time.RFC3339)
	if err := database.Connection.Save(&signin).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to sign out from session",
			handler.ErrInternal,
		)
	}

	handler.RemoveSessionFromCache(session.ID)

	return handler.SendSuccess[any](c, nil)
}

func (h *Handler) GetUserOrganizationMemberships(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(
			c,
			nil,
			"Unauthorized",
		)
	}

	memberships := []model.OrganizationMembership{}
	if err := database.Connection.Where(
		"user_id = ?",
		session.ActiveSignin.UserID,
	).Preload(
		clause.Associations,
	).Find(&memberships).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to get user organization memberships",
		)
	}

	return handler.SendSuccess(
		c,
		memberships,
	)
}

func (h *Handler) GetUserWorkspaceMemberships(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(
			c,
			nil,
			"Unauthorized",
		)
	}

	memberships := []model.WorkspaceMembership{}
	query := database.Connection.Where(
		"user_id = ?",
		session.ActiveSignin.UserID,
	).Preload(
		clause.Associations,
	)

	orgID := c.Query("org_id")
	if orgID != "" {
		query = query.Where(
			"organization_id = ?",
			orgID,
		)
	}

	if err := query.Find(&memberships).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			nil,
			"Failed to get user workspace memberships",
		)
	}

	return handler.SendSuccess(
		c,
		memberships,
	)
}
