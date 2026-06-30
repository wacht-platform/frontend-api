package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/model"
	"github.com/wacht-platform/frontend-api/utils"
	"gorm.io/gorm"
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

func (h *Handler) BeginPasskeyLogin(c fiber.Ctx) error {
	d := handler.GetDeployment(c)
	session := handler.GetSession(c)

	if err := requireChallenge(c, ""); err != nil {
		return err
	}

	if d.AuthSettings.Passkey == nil || !d.AuthSettings.Passkey.Enabled {
		return handler.SendForbidden(c, nil, "Passkeys are not enabled", handler.ErrPasskeyNotEnabled)
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

	options, sessionData, err := webAuthn.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationPreferred),
	)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to begin passkey login")
	}

	sessionKey := fmt.Sprintf("passkey_login:%d", session.ID)
	sessionJSON, _ := json.Marshal(sessionData)
	database.Redis.Set(c.RequestCtx(), sessionKey, sessionJSON, 5*time.Minute)

	return handler.SendSuccess(c, fiber.Map{
		"options": options,
	})
}

func (h *Handler) FinishPasskeyLogin(c fiber.Ctx) error {
	d := handler.GetDeployment(c)
	session := handler.GetSession(c)

	if d.AuthSettings.Passkey == nil || !d.AuthSettings.Passkey.Enabled {
		return handler.SendForbidden(c, nil, "Passkeys are not enabled", handler.ErrPasskeyNotEnabled)
	}

	sessionKey := fmt.Sprintf("passkey_login:%d", session.ID)
	sessionJSON, err := database.Redis.Get(c.RequestCtx(), sessionKey).Bytes()
	if err != nil {
		return handler.SendBadRequest(c, nil, "Login session expired")
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

	discoverHandler := func(rawID, userHandle []byte) (webauthn.User, error) {
		var passkey model.UserPasskey
		if err := database.Connection.Where("credential_id = ?", rawID).First(&passkey).Error; err != nil {
			return nil, fmt.Errorf("passkey not found")
		}

		var user model.User
		if err := database.Connection.First(&user, passkey.UserID).Error; err != nil {
			return nil, fmt.Errorf("user not found")
		}

		var allPasskeys []model.UserPasskey
		database.Connection.Where("user_id = ?", user.ID).Find(&allPasskeys)

		credentials := make([]webauthn.Credential, len(allPasskeys))
		for i, pk := range allPasskeys {
			credentials[i] = webauthn.Credential{
				ID:              pk.CredentialID,
				PublicKey:       pk.PublicKey,
				AttestationType: "",
				Authenticator: webauthn.Authenticator{
					AAGUID:    pk.AAGUID,
					SignCount: pk.SignCount,
				},
				Flags: webauthn.CredentialFlags{
					BackupEligible: pk.BackedUp,
					BackupState:    pk.BackedUp,
				},
			}
		}

		return &PasskeyUser{
			ID:          user.ID,
			Name:        getUserIdentifier(&user),
			DisplayName: fmt.Sprintf("%s %s", user.FirstName, user.LastName),
			Credentials: credentials,
		}, nil
	}

	// Parse FormData fields and reconstruct JSON for WebAuthn library
	credId := c.FormValue("id")
	rawId := c.FormValue("rawId")
	credType := c.FormValue("type")
	clientDataJSON := c.FormValue("clientDataJSON")
	authenticatorData := c.FormValue("authenticatorData")
	signature := c.FormValue("signature")
	userHandle := c.FormValue("userHandle")

	// Build the assertion response JSON that WebAuthn library expects
	assertionJSON := map[string]any{
		"id":    credId,
		"rawId": rawId,
		"type":  credType,
		"response": map[string]any{
			"clientDataJSON":    clientDataJSON,
			"authenticatorData": authenticatorData,
			"signature":         signature,
		},
	}
	if userHandle != "" {
		assertionJSON["response"].(map[string]any)["userHandle"] = userHandle
	}

	// Create a new HTTP request with JSON body for WebAuthn library
	jsonBody, _ := json.Marshal(assertionJSON)
	httpReq, err := http.NewRequest("POST", "/", strings.NewReader(string(jsonBody)))
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create request")
	}
	httpReq.Header.Set("Content-Type", "application/json")

	credential, err := webAuthn.FinishDiscoverableLogin(discoverHandler, sessionData, httpReq)
	if err != nil {
		return handler.SendUnauthorized(c, err, "Passkey authentication failed", handler.ErrInvalidCredentials)
	}

	var passkey model.UserPasskey
	if err := database.Connection.Where("credential_id = ?", credential.ID).First(&passkey).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to find passkey")
	}

	now := time.Now()
	database.Connection.Model(&passkey).Updates(map[string]any{
		"sign_count":   credential.Authenticator.SignCount,
		"last_used_at": now,
	})

	var user model.User
	if err := database.Connection.Preload("PrimaryEmailAddress").Preload("PrimaryPhoneNumber").First(&user, passkey.UserID).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to load user")
	}

	if user.Disabled {
		return handler.SendForbidden(c, nil, "Account is disabled", handler.ErrUserDisabled)
	}

	for _, signin := range session.Signins {
		if signin.UserID != nil && *signin.UserID == user.ID {
			return handler.SendBadRequest(
				c,
				nil,
				"User already signed in",
				handler.ErrUserAlreadySignedIn,
			)
		}
	}

	attempt := h.service.CreateSignInAttempt(
		&user.ID,
		nil,
		session.ID,
		model.SignInMethodPasskey,
		[]model.SignInAttemptStep{},
		true,
		&d,
	)

	var signIn *model.Signin
	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(attempt).Error; err != nil {
			return err
		}

		signIn = h.service.CreateSignin(user.ID, session.ID, c, d.AuthSettings.SessionValidityPeriod)
		if err := tx.Create(signIn).Error; err != nil {
			return err
		}

		if err := tx.Model(&model.Session{}).Where("id = ?", session.ID).Update("active_signin_id", signIn.ID).Error; err != nil {
			return err
		}

		utils.PublishSignInEvent(d.ID, &user, "passkey", nil, signIn, c)

		return nil
	})

	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create sign-in")
	}

	h.service.TrackMAU(d.ID, user.ID)

	signIn.User = &user

	database.Redis.Del(c.RequestCtx(), sessionKey)

	session.SigninAttempts = append(session.SigninAttempts, *attempt)
	handler.RemoveSessionFromCacheAndLocals(c, session.ID)
	return handler.SendSuccess(c, session)
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
