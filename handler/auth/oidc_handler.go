package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/model"
	"github.com/wacht-platform/frontend-api/pkg/idgen"
	"github.com/wacht-platform/frontend-api/service"
	"github.com/wacht-platform/frontend-api/utils"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

// OIDCLogin initiates the OIDC authentication flow
func (h *Handler) OIDCLogin(c fiber.Ctx, connection *model.EnterpriseConnection) error {
	redirectURI := c.Query("redirect_uri")

	deployment := handler.GetDeployment(c)
	session := handler.GetSession(c)

	if connection.OIDCIssuerURL == nil || *connection.OIDCIssuerURL == "" {
		return handler.SendBadRequest(c, nil, "OIDC issuer URL not configured")
	}

	if connection.OIDCClientID == nil || *connection.OIDCClientID == "" {
		return handler.SendBadRequest(c, nil, "OIDC client ID not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, *connection.OIDCIssuerURL)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to discover OIDC provider")
	}

	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to generate state")
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to generate nonce")
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)

	codeVerifierBytes := make([]byte, 64)
	if _, err := rand.Read(codeVerifierBytes); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to generate code verifier")
	}
	codeVerifier := base64.RawURLEncoding.EncodeToString(codeVerifierBytes)

	codeChallenge := generateCodeChallenge(codeVerifier)

	attempt := model.NewSignInAttempt(model.SignInMethodEnterpriseSso)
	attempt.SessionID = session.ID
	attempt.EnterpriseConnectionID = &connection.ID
	oidcData := fmt.Sprintf("%s|%s|%s", state, nonce, codeVerifier)
	attempt.OIDCState = &oidcData

	if err := database.Connection.Create(attempt).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create sign-in attempt")
	}

	callbackURL := fmt.Sprintf("https://%s/auth/sso/oidc/callback", deployment.BackendHost)
	scopes := []string{oidc.ScopeOpenID, "profile", "email"}
	if connection.OIDCScopes != nil && *connection.OIDCScopes != "" {
		scopes = strings.Split(*connection.OIDCScopes, " ")
	}

	oauth2Config := oauth2.Config{
		ClientID:     *connection.OIDCClientID,
		ClientSecret: "",
		RedirectURL:  callbackURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	if connection.OIDCClientSecret != nil {
		oauth2Config.ClientSecret = *connection.OIDCClientSecret
	}

	relayData := encodeOIDCRelayState(attempt.ID, redirectURI, deployment.ID, state)

	authURL := oauth2Config.AuthCodeURL(
		relayData,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	return handler.SendSuccess(c, fiber.Map{
		"sso_url": authURL,
		"session": session,
	})
}

// OIDCCallback handles the callback from the OIDC Identity Provider
func (h *Handler) OIDCCallback(c fiber.Ctx) error {
	code := c.Query("code")
	stateParam := c.Query("state")
	errorParam := c.Query("error")

	if errorParam != "" {
		errorDesc := c.Query("error_description")
		return handler.SendBadRequest(c, nil, fmt.Sprintf("IdP error: %s - %s", errorParam, errorDesc))
	}

	if code == "" {
		return handler.SendBadRequest(c, nil, "Authorization code is required")
	}

	deployment := handler.GetDeployment(c)

	attemptID, redirectURI, state, err := decodeOIDCRelayState(stateParam, deployment.ID)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid state parameter")
	}

	var attempt model.SignInAttempt
	if err := database.Connection.Where("id = ?", attemptID).First(&attempt).Error; err != nil {
		return handler.SendBadRequest(c, nil, "Invalid or expired authentication attempt")
	}

	if attempt.OIDCState == nil {
		return handler.SendBadRequest(c, nil, "Invalid state - missing OIDC data")
	}

	storedState, storedNonce, storedCodeVerifier, err := parseOIDCData(*attempt.OIDCState)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid state - corrupted OIDC data")
	}

	if storedState != state {
		return handler.SendBadRequest(c, nil, "Invalid state - possible CSRF attack")
	}

	if attempt.Completed {
		return handler.SendBadRequest(c, nil, "Authentication attempt already completed")
	}

	if time.Since(attempt.CreatedAt) > 10*time.Minute {
		return handler.SendBadRequest(c, nil, "Authentication attempt has expired")
	}

	var session model.Session
	if err := database.Connection.Where("id = ?", attempt.SessionID).
		Preload("Signins").
		Preload("SigninAttempts").
		First(&session).Error; err != nil {
		return handler.SendBadRequest(c, nil, "Session not found")
	}

	if attempt.EnterpriseConnectionID == nil {
		return handler.SendBadRequest(c, nil, "Invalid sign-in attempt")
	}

	ssoService := service.NewSSOService()
	connection, err := ssoService.GetConnectionByID(*attempt.EnterpriseConnectionID)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid enterprise connection")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, *connection.OIDCIssuerURL)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to discover OIDC provider")
	}

	callbackURL := fmt.Sprintf("https://%s/auth/sso/oidc/callback", deployment.BackendHost)
	scopes := []string{oidc.ScopeOpenID, "profile", "email"}
	if connection.OIDCScopes != nil && *connection.OIDCScopes != "" {
		scopes = strings.Split(*connection.OIDCScopes, " ")
	}

	oauth2Config := oauth2.Config{
		ClientID:     *connection.OIDCClientID,
		ClientSecret: "",
		RedirectURL:  callbackURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	if connection.OIDCClientSecret != nil {
		oauth2Config.ClientSecret = *connection.OIDCClientSecret
	}

	token, err := oauth2Config.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", storedCodeVerifier),
	)
	if err != nil {
		return handler.SendBadRequest(c, nil, fmt.Sprintf("Failed to exchange code: %v", err))
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: *connection.OIDCClientID,
	})

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return handler.SendBadRequest(c, nil, "No id_token in token response")
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return handler.SendBadRequest(c, nil, fmt.Sprintf("Failed to verify ID token: %v", err))
	}

	if idToken.Nonce != storedNonce {
		return handler.SendBadRequest(c, nil, "Invalid nonce - possible replay attack")
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Subject       string `json:"sub"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return handler.SendBadRequest(c, nil, "Failed to parse ID token claims")
	}

	var rawClaims map[string]interface{}
	idToken.Claims(&rawClaims)

	userEmail := strings.ToLower(claims.Email)
	if userEmail == "" {
		return handler.SendBadRequest(c, nil, "No email found in ID token")
	}

	if claims.EmailVerified != nil && !*claims.EmailVerified {
		return handler.SendBadRequest(c, nil, "Email address not verified by identity provider")
	}

	firstName := claims.GivenName
	lastName := claims.FamilyName

	if connection.AttributeMapping != nil {
		if customAttr, ok := connection.AttributeMapping["first_name"].(string); ok && customAttr != "" {
			if val, exists := rawClaims[customAttr]; exists {
				if strVal, ok := val.(string); ok {
					firstName = strVal
				}
			}
		}
		if customAttr, ok := connection.AttributeMapping["last_name"].(string); ok && customAttr != "" {
			if val, exists := rawClaims[customAttr]; exists {
				if strVal, ok := val.(string); ok {
					lastName = strVal
				}
			}
		}
	}

	var user *model.User
	var created bool

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		var email model.UserEmailAddress
		err := tx.Where("email_address = ? AND deployment_id = ?", userEmail, deployment.ID).
			Preload("User").
			First(&email).Error

		if err == gorm.ErrRecordNotFound {
			if !connection.JitEnabled {
				return fmt.Errorf("user not found and JIT provisioning is disabled - please contact your administrator")
			}
			user, err = h.createOIDCUser(tx, userEmail, firstName, lastName, &deployment)
			if err != nil {
				return err
			}
			created = true
		} else if err != nil {
			return err
		} else {
			user = &email.User
			created = false
		}

		if err := h.service.ValidateIPCountryRestrictions(c, deployment.Restrictions); err != nil {
			return err
		}

		var existingSignIn *model.Signin
		for i := range session.Signins {
			if session.Signins[i].UserID != nil && *session.Signins[i].UserID == user.ID {
				existingSignIn = &session.Signins[i]
				break
			}
		}

		var signIn *model.Signin
		if existingSignIn != nil {
			signIn = existingSignIn
		} else {
			signIn = h.service.CreateSignin(user.ID, session.ID, c, deployment.AuthSettings.SessionValidityPeriod)
			if err := tx.Create(signIn).Error; err != nil {
				return err
			}
			session.Signins = append(session.Signins, *signIn)
		}

		if err := tx.Model(&model.Session{}).Where("id = ?", session.ID).Update("active_signin_id", signIn.ID).Error; err != nil {
			return err
		}

		session.ActiveSigninID = &signIn.ID

		attempt.Completed = true
		attempt.UserID = &user.ID
		attempt.FirstMethodAuthenticated = true
		attempt.OIDCState = nil
		if err := tx.Save(&attempt).Error; err != nil {
			return err
		}

		utils.PublishWebhookEvent(deployment.ID, "session.created", session.ID, "session")

		if created {
			utils.PublishSignUpEvent(deployment.ID, user, "enterprise_sso", &userEmail, c)
		}
		utils.PublishSignInEvent(deployment.ID, user, "enterprise_sso", &userEmail, c)

		return nil
	})

	if err != nil {
		// Check if this is a JIT provisioning error - redirect with error params to sign-in page
		if strings.Contains(err.Error(), "JIT provisioning is disabled") {
			// Redirect to sign-in page (not app root) so the error can be displayed
			errorRedirectURI := deployment.UISettings.SignInPageURL
			if errorRedirectURI == "" && deployment.FrontendHost != "" {
				errorRedirectURI = fmt.Sprintf("https://%s/sign-in", deployment.FrontendHost)
			}
			if errorRedirectURI != "" {
				parsedURL, parseErr := url.Parse(errorRedirectURI)
				if parseErr == nil {
					q := parsedURL.Query()
					q.Set("error", "access_denied")
					q.Set("error_description", "User not found and automatic provisioning is disabled. Please contact your administrator.")
					parsedURL.RawQuery = q.Encode()
					return c.Redirect().Status(fiber.StatusFound).To(parsedURL.String())
				}
			}
			return handler.SendForbidden(c, nil, "User not found and JIT provisioning is disabled - please contact your administrator")
		}
		return handler.SendInternalServerError(c, err, "Failed to complete OIDC authentication")
	}

	h.service.TrackMAU(deployment.ID, user.ID)
	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	if redirectURI == "" {
		redirectURI = deployment.UISettings.AfterSigninRedirectURL
	}
	if redirectURI == "" && deployment.FrontendHost != "" {
		redirectURI = fmt.Sprintf("https://%s", deployment.FrontendHost)
	}

	if redirectURI != "" {
		if !deployment.IsProduction() {
			var keypair model.DeploymentKeyPair
			if err := database.Connection.Where("deployment_id = ?", deployment.ID).First(&keypair).Error; err == nil {
				token, err := utils.SignNewJWT(
					session.ID,
					deployment.BackendHost,
					time.Now().Add(6*time.Hour),
					keypair,
					database.Connection,
				)
				if err == nil {
					parsedURL, parseErr := url.Parse(redirectURI)
					if parseErr == nil {
						q := parsedURL.Query()
						q.Set("__dev_session__", token)
						parsedURL.RawQuery = q.Encode()
						redirectURI = parsedURL.String()
					}
				}
			}
		}
		return c.Redirect().Status(fiber.StatusFound).To(redirectURI)
	}

	return handler.SendSuccess(c, fiber.Map{
		"session": session,
	})
}

// createOIDCUser creates a new user from OIDC claims (JIT provisioning)
func (h *Handler) createOIDCUser(
	tx *gorm.DB,
	email string,
	firstName string,
	lastName string,
	deployment *model.Deployment,
) (*model.User, error) {
	primaryAddressID := idgen.NextID()

	user := model.User{
		Model: model.Model{
			ID: idgen.NextID(),
		},
		FirstName:             firstName,
		LastName:              lastName,
		SchemaVersion:         model.SchemaVersionV1,
		SecondFactorPolicy:    deployment.AuthSettings.SecondFactorPolicy,
		DeploymentID:          deployment.ID,
		PrimaryEmailAddressID: &primaryAddressID,
	}

	if err := tx.Create(&user).Error; err != nil {
		return nil, err
	}

	emailRecord := model.UserEmailAddress{
		Model:                model.Model{ID: primaryAddressID},
		DeploymentID:         deployment.ID,
		EmailAddress:         email,
		IsPrimary:            true,
		Verified:             true,
		VerifiedAt:           time.Now(),
		VerificationStrategy: model.VerificationStrategyEnterpriseSso,
		UserID:               &user.ID,
	}

	if err := tx.Create(&emailRecord).Error; err != nil {
		return nil, err
	}

	if err := h.service.CheckAndAddUserToOrganizationByDomain(tx, user.ID, email, deployment.ID); err != nil {
		return nil, err
	}

	return &user, nil
}

// generateCodeChallenge creates a PKCE code challenge from a verifier
func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// parseOIDCData extracts state, nonce, and code verifier from stored OIDC data
func parseOIDCData(data string) (state, nonce, codeVerifier string, err error) {
	parts := strings.SplitN(data, "|", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid OIDC data format")
	}
	return parts[0], parts[1], parts[2], nil
}

// encodeOIDCRelayState encodes attempt ID, redirect URI, deployment ID and state into a single string
func encodeOIDCRelayState(attemptID uint64, redirectURI string, deploymentID uint64, state string) string {
	data := fmt.Sprintf("%d|%s|%d|%s", attemptID, redirectURI, deploymentID, state)
	return base64.URLEncoding.EncodeToString([]byte(data))
}

// decodeOIDCRelayState decodes the relay state string
func decodeOIDCRelayState(relayState string, expectedDeploymentID uint64) (uint64, string, string, error) {
	if relayState == "" {
		return 0, "", "", fmt.Errorf("empty relay state")
	}

	data, err := base64.URLEncoding.DecodeString(relayState)
	if err != nil {
		return 0, "", "", fmt.Errorf("failed to decode relay state: %v", err)
	}

	parts := strings.SplitN(string(data), "|", 4)
	if len(parts) != 4 {
		return 0, "", "", fmt.Errorf("invalid relay state format")
	}

	attemptID, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, "", "", fmt.Errorf("invalid attempt ID in relay state")
	}

	redirectURI := parts[1]

	deploymentID, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return 0, "", "", fmt.Errorf("invalid deployment ID in relay state")
	}

	if deploymentID != expectedDeploymentID {
		return 0, "", "", fmt.Errorf("deployment ID mismatch in relay state")
	}

	state := parts[3]

	return attemptID, redirectURI, state, nil
}
