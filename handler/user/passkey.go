package user

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/model"
)

type PasskeyUser struct {
	ID          uint64
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

func (u *PasskeyUser) WebAuthnID() []byte {
	return fmt.Appendf(nil, "%d", u.ID)
}

func (u *PasskeyUser) WebAuthnName() string {
	return u.Name
}

func (u *PasskeyUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u *PasskeyUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func (h *Handler) GetPasskeys(c fiber.Ctx) error {
	session := handler.GetSession(c)
	d := handler.GetDeployment(c)

	if d.AuthSettings.Passkey == nil || !d.AuthSettings.Passkey.Enabled {
		return handler.SendForbidden(c, nil, "Passkeys are not enabled", handler.ErrPasskeyNotEnabled)
	}

	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in", handler.ErrUnauthorized)
	}

	var passkeys []model.UserPasskey
	if err := database.Connection.Where("user_id = ?", session.ActiveSignin.UserID).Find(&passkeys).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to fetch passkeys")
	}

	return handler.SendSuccess(c, passkeys)
}

func (h *Handler) BeginPasskeyRegistration(c fiber.Ctx) error {
	d := handler.GetDeployment(c)
	session := handler.GetSession(c)

	if d.AuthSettings.Passkey == nil || !d.AuthSettings.Passkey.Enabled {
		return handler.SendForbidden(c, nil, "Passkeys are not enabled for this deployment", handler.ErrPasskeyNotEnabled)
	}

	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in", handler.ErrUnauthorized)
	}

	var user model.User
	if err := database.Connection.Preload("PrimaryEmailAddress").Preload("PrimaryPhoneNumber").First(&user, session.ActiveSignin.UserID).Error; err != nil {
		return handler.SendUnauthorized(c, nil, "User not found", handler.ErrUnauthorized)
	}

	wconfig := &webauthn.Config{
		RPDisplayName: getRPDisplayName(d),
		RPID:          getRPID(d),
		RPOrigins:     getRPOrigins(d, c.Get("Origin")),
	}

	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to initialize WebAuthn")
	}

	var existingPasskeys []model.UserPasskey
	database.Connection.Where("user_id = ?", user.ID).Find(&existingPasskeys)

	existingCreds := make([]webauthn.Credential, len(existingPasskeys))
	for i, pk := range existingPasskeys {
		existingCreds[i] = webauthn.Credential{
			ID:        pk.CredentialID,
			PublicKey: pk.PublicKey,
		}
	}

	passkeyUser := &PasskeyUser{
		ID:          user.ID,
		Name:        getUserIdentifier(&user),
		DisplayName: fmt.Sprintf("%s %s", user.FirstName, user.LastName),
		Credentials: existingCreds,
	}

	options, sessionData, err := webAuthn.BeginRegistration(
		passkeyUser,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to begin passkey registration")
	}

	sessionKey := fmt.Sprintf("passkey_reg:%d:%d", user.ID, session.ID)
	sessionJSON, _ := json.Marshal(sessionData)
	database.Redis.Set(c.RequestCtx(), sessionKey, sessionJSON, 5*time.Minute)

	return handler.SendSuccess(c, fiber.Map{
		"options": options,
	})
}

func (h *Handler) FinishPasskeyRegistration(c fiber.Ctx) error {
	d := handler.GetDeployment(c)
	session := handler.GetSession(c)

	name := c.Query("name", c.FormValue("name", ""))

	if d.AuthSettings.Passkey == nil || !d.AuthSettings.Passkey.Enabled {
		return handler.SendForbidden(c, nil, "Passkeys are not enabled", handler.ErrPasskeyNotEnabled)
	}

	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in", handler.ErrUnauthorized)
	}

	var user model.User
	if err := database.Connection.Preload("PrimaryEmailAddress").Preload("PrimaryPhoneNumber").First(&user, session.ActiveSignin.UserID).Error; err != nil {
		return handler.SendUnauthorized(c, nil, "User not found", handler.ErrUnauthorized)
	}

	sessionKey := fmt.Sprintf("passkey_reg:%d:%d", user.ID, session.ID)
	sessionJSON, err := database.Redis.Get(c.RequestCtx(), sessionKey).Bytes()
	if err != nil {
		return handler.SendBadRequest(c, nil, "Registration session expired")
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &sessionData); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to parse session data")
	}

	wconfig := &webauthn.Config{
		RPDisplayName: getRPDisplayName(d),
		RPID:          getRPID(d),
		RPOrigins:     getRPOrigins(d, c.Get("Origin")),
	}

	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to initialize WebAuthn")
	}

	passkeyUser := &PasskeyUser{
		ID:          user.ID,
		Name:        getUserIdentifier(&user),
		DisplayName: fmt.Sprintf("%s %s", user.FirstName, user.LastName),
	}

	httpReq, err := adaptor.ConvertRequest(c, false)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to convert request")
	}

	credential, err := webAuthn.FinishRegistration(passkeyUser, sessionData, httpReq)
	if err != nil {
		return handler.SendBadRequest(c, err, "Failed to verify passkey registration")
	}

	if name == "" {
		name = fmt.Sprintf("Passkey %d", time.Now().Unix())
	}

	deviceType := "cross-platform"
	if credential.Authenticator.Attachment == protocol.Platform {
		deviceType = "platform"
	}

	transports := make([]string, len(credential.Transport))
	for i, t := range credential.Transport {
		transports[i] = string(t)
	}

	passkey := model.NewUserPasskey(
		user.ID,
		name,
		credential.ID,
		credential.PublicKey,
		credential.Authenticator.AAGUID,
		credential.Authenticator.SignCount,
		transports,
		credential.Flags.BackupEligible,
		deviceType,
	)

	if err := database.Connection.Create(passkey).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to save passkey")
	}

	database.Redis.Del(c.RequestCtx(), sessionKey)

	return handler.SendSuccess(c, fiber.Map{
		"passkey": passkey,
	})
}

func (h *Handler) DeletePasskey(c fiber.Ctx) error {
	session := handler.GetSession(c)
	d := handler.GetDeployment(c)

	if d.AuthSettings.Passkey == nil || !d.AuthSettings.Passkey.Enabled {
		return handler.SendForbidden(c, nil, "Passkeys are not enabled", handler.ErrPasskeyNotEnabled)
	}

	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in", handler.ErrUnauthorized)
	}

	passKeyID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, err, "Invalid passkey ID")
	}

	var passkey model.UserPasskey
	if err := database.Connection.Where("id = ? AND user_id = ?", passKeyID, session.ActiveSignin.UserID).First(&passkey).Error; err != nil {
		return handler.SendNotFound(c, err, "Passkey not found")
	}

	if err := database.Connection.Delete(&passkey).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to delete passkey")
	}

	return handler.SendSuccess(c, fiber.Map{
		"message": "Passkey deleted successfully",
	})
}

type RenamePasskeyRequest struct {
	Name string `form:"name"`
}

func (h *Handler) RenamePasskey(c fiber.Ctx) error {
	session := handler.GetSession(c)
	d := handler.GetDeployment(c)

	b, validation := handler.Validate[RenamePasskeyRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	if d.AuthSettings.Passkey == nil || !d.AuthSettings.Passkey.Enabled {
		return handler.SendForbidden(c, nil, "Passkeys are not enabled", handler.ErrPasskeyNotEnabled)
	}

	if session.ActiveSignin == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in", handler.ErrUnauthorized)
	}

	passKeyID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, err, "Invalid passkey ID")
	}

	var passkey model.UserPasskey
	if err := database.Connection.Where("id = ? AND user_id = ?", passKeyID, session.ActiveSignin.UserID).First(&passkey).Error; err != nil {
		return handler.SendNotFound(c, err, "Passkey not found")
	}

	if b.Name == "" {
		return handler.SendBadRequest(c, nil, "Name is required")
	}

	if err := database.Connection.Model(&passkey).Update("name", b.Name).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to rename passkey")
	}

	passkey.Name = b.Name
	return handler.SendSuccess(c, passkey)
}

func getRPDisplayName(d model.Deployment) string {
	if d.UISettings.AppName != "" {
		return d.UISettings.AppName
	}
	return "Wacht"
}

func getRPID(d model.Deployment) string {
	host := d.BackendHost
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

func getRPOrigins(d model.Deployment, requestOrigin string) []string {
	origins := []string{}
	if d.FrontendHost != "" {
		origins = append(origins, "https://"+d.FrontendHost)
	}
	if d.BackendHost != "" {
		origins = append(origins, "https://"+d.BackendHost)
	}
	if requestOrigin != "" && !slices.Contains(origins, requestOrigin) {
		origins = append(origins, requestOrigin)
	}
	return origins
}

func getUserIdentifier(user *model.User) string {
	if user.PrimaryEmailAddress != nil {
		return user.PrimaryEmailAddress.EmailAddress
	}
	if user.PrimaryPhoneNumber != nil {
		return user.PrimaryPhoneNumber.PhoneNumber
	}
	if user.Username != "" {
		return user.Username
	}
	return fmt.Sprintf("user_%d", user.ID)
}
