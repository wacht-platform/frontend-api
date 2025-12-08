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
	"github.com/godruoyi/go-snowflake"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/service"
	"github.com/ilabs/wacht-fe/utils"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

// OIDCLogin initiates the OIDC authentication flow
func (h *Handler) OIDCLogin(c *fiber.Ctx, connection *model.EnterpriseConnection) error {
	redirectURI := c.Query("redirect_uri")

	deployment := handler.GetDeployment(c)
	session := handler.GetSession(c)

	if connection.OIDCIssuerURL == nil || *connection.OIDCIssuerURL == "" {
		return handler.SendBadRequest(c, nil, "OIDC issuer URL not configured")
	}

	if connection.OIDCClientID == nil || *connection.OIDCClientID == "" {
		return handler.SendBadRequest(c, nil, "OIDC client ID not configured")
	}

	ctx := context.Background()

	// Use OIDC Discovery to get proper endpoints
	provider, err := oidc.NewProvider(ctx, *connection.OIDCIssuerURL)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to discover OIDC provider")
	}

	// Generate random state for CSRF protection (32 bytes for security)
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to generate state")
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	// Generate nonce for ID token replay protection (32 bytes)
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to generate nonce")
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)

	// Generate PKCE code verifier (43-128 chars, we use 64 bytes = 86 chars base64)
	codeVerifierBytes := make([]byte, 64)
	if _, err := rand.Read(codeVerifierBytes); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to generate code verifier")
	}
	codeVerifier := base64.RawURLEncoding.EncodeToString(codeVerifierBytes)

	// Generate PKCE code challenge (SHA256 hash of verifier, base64url encoded)
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Create sign-in attempt and store security parameters
	attempt := model.NewSignInAttempt(model.SignInMethodEnterpriseSso)
	attempt.SessionID = session.ID
	attempt.EnterpriseConnectionID = &connection.ID
	// Store state, nonce, and code verifier as pipe-separated string
	oidcData := fmt.Sprintf("%s|%s|%s", state, nonce, codeVerifier)
	attempt.OIDCState = &oidcData

	if err := database.Connection.Create(attempt).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create sign-in attempt")
	}

	// Build OAuth2 config using discovered endpoints
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

	// Encode attempt ID, redirect URI and deployment ID in state parameter
	relayData := encodeOIDCRelayState(attempt.ID, redirectURI, deployment.ID, state)

	// Build auth URL with PKCE and nonce
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
func (h *Handler) OIDCCallback(c *fiber.Ctx) error {
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

	// Decode relay state
	attemptID, redirectURI, state, err := decodeOIDCRelayState(stateParam, deployment.ID)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid state parameter")
	}

	// Find the sign-in attempt
	var attempt model.SignInAttempt
	if err := database.Connection.Where("id = ?", attemptID).First(&attempt).Error; err != nil {
		return handler.SendBadRequest(c, nil, "Invalid or expired authentication attempt")
	}

	// Validate CSRF state and extract stored parameters
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

	// Check if state was already used (prevent replay)
	if attempt.Completed {
		return handler.SendBadRequest(c, nil, "Authentication attempt already completed")
	}

	// Check expiry
	if time.Since(attempt.CreatedAt) > 10*time.Minute {
		return handler.SendBadRequest(c, nil, "Authentication attempt has expired")
	}

	// Get session
	var session model.Session
	if err := database.Connection.Where("id = ?", attempt.SessionID).
		Preload("Signins").
		Preload("SigninAttempts").
		First(&session).Error; err != nil {
		return handler.SendBadRequest(c, nil, "Session not found")
	}

	// Get enterprise connection
	if attempt.EnterpriseConnectionID == nil {
		return handler.SendBadRequest(c, nil, "Invalid sign-in attempt")
	}

	ssoService := service.NewSSOService()
	connection, err := ssoService.GetConnectionByID(*attempt.EnterpriseConnectionID)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid enterprise connection")
	}

	ctx := context.Background()

	// Use OIDC Discovery for proper endpoints
	provider, err := oidc.NewProvider(ctx, *connection.OIDCIssuerURL)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to discover OIDC provider")
	}

	// Build OAuth2 config using discovered endpoints
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

	// Exchange code for tokens with PKCE verifier
	token, err := oauth2Config.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", storedCodeVerifier),
	)
	if err != nil {
		return handler.SendBadRequest(c, nil, fmt.Sprintf("Failed to exchange code: %v", err))
	}

	// Create verifier with nonce validation
	verifier := provider.Verifier(&oidc.Config{
		ClientID: *connection.OIDCClientID,
	})

	// Extract and verify ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return handler.SendBadRequest(c, nil, "No id_token in token response")
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return handler.SendBadRequest(c, nil, fmt.Sprintf("Failed to verify ID token: %v", err))
	}

	// Validate nonce to prevent replay attacks
	if idToken.Nonce != storedNonce {
		return handler.SendBadRequest(c, nil, "Invalid nonce - possible replay attack")
	}

	// Extract claims
	var claims struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"` // Pointer to detect missing claim
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Subject       string `json:"sub"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return handler.SendBadRequest(c, nil, "Failed to parse ID token claims")
	}

	userEmail := strings.ToLower(claims.Email)
	if userEmail == "" {
		return handler.SendBadRequest(c, nil, "No email found in ID token")
	}

	// Check email_verified claim (industry standard)
	// Some IdPs don't include this claim, so we only reject if explicitly false
	if claims.EmailVerified != nil && !*claims.EmailVerified {
		return handler.SendBadRequest(c, nil, "Email address not verified by identity provider")
	}

	// Find or create user
	var user *model.User
	var created bool

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		var email model.UserEmailAddress
		err := tx.Where("email_address = ? AND deployment_id = ?", userEmail, deployment.ID).
			Preload("User").
			First(&email).Error

		if err == gorm.ErrRecordNotFound {
			user, err = h.createOIDCUser(tx, userEmail, claims.GivenName, claims.FamilyName, connection, &deployment)
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
		return handler.SendInternalServerError(c, err, "Failed to complete OIDC authentication")
	}

	h.service.TrackMAU(deployment.ID, user.ID)
	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	// Determine redirect URI
	if redirectURI == "" {
		redirectURI = deployment.UISettings.AfterSigninRedirectURL
	}
	if redirectURI == "" && deployment.FrontendHost != "" {
		redirectURI = fmt.Sprintf("https://%s", deployment.FrontendHost)
	}

	if redirectURI != "" {
		// For staging deployments, add session token to URL
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
		return c.Redirect(redirectURI, fiber.StatusFound)
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
	connection *model.EnterpriseConnection,
	deployment *model.Deployment,
) (*model.User, error) {
	primaryAddressID := snowflake.ID()

	user := model.User{
		Model: model.Model{
			ID: snowflake.ID(),
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
