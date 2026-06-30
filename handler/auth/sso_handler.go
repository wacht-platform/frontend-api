package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/model"
	"github.com/wacht-platform/frontend-api/pkg/idgen"
	"github.com/wacht-platform/frontend-api/service"
	"github.com/wacht-platform/frontend-api/utils"
	"golang.org/x/net/publicsuffix"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var errAttemptAlreadyCompleted = errors.New("authentication attempt already completed")

func (h *Handler) SSOLogin(c fiber.Ctx) error {
	connectionIDStr := c.Query("connection_id")
	redirectURI := c.Query("redirect_uri")

	if connectionIDStr == "" {
		return handler.SendBadRequest(c, nil, "connection_id is required")
	}

	connectionID, err := strconv.ParseUint(connectionIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid connection_id")
	}

	deployment := handler.GetDeployment(c)
	session := handler.GetSession(c)

	if err := requireChallenge(c, ""); err != nil {
		return err
	}

	ssoService := service.NewSSOService()
	connection, err := ssoService.GetConnectionByID(connectionID)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid enterprise connection")
	}

	if connection.DeploymentID != deployment.ID {
		return handler.SendBadRequest(c, nil, "Invalid enterprise connection for this deployment")
	}

	if connection.Domain == nil || !connection.Domain.Verified {
		return handler.SendBadRequest(c, nil, "Enterprise connection is not bound to a verified domain")
	}

	if redirectURI != "" {
		if err := validateSSORedirectURI(&deployment, redirectURI); err != nil {
			return handler.SendBadRequest(c, nil, err.Error())
		}
	}

	if connection.Protocol == "oidc" {
		return h.OIDCLogin(c, connection)
	}

	var keypair model.DeploymentKeyPair
	if err := database.Connection.Where("deployment_id = ?", deployment.ID).First(&keypair).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to get deployment keypair")
	}

	sp, err := buildServiceProvider(connection, &deployment, keypair)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to build SAML service provider")
	}

	authnRequest, _ := sp.MakeAuthenticationRequest(
		connection.IdpSSOURL,
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)

	requestID := authnRequest.ID
	attempt := model.NewSignInAttempt(model.SignInMethodEnterpriseSso)
	attempt.SessionID = session.ID
	attempt.EnterpriseConnectionID = &connection.ID
	attempt.SamlRequestID = &requestID

	if err := database.Connection.Create(attempt).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create sign-in attempt")
	}

	relayState := encodeRelayState(attempt.ID, redirectURI, deployment.ID)
	redirectURL, _ := authnRequest.Redirect(relayState, sp)

	return handler.SendSuccess(c, fiber.Map{
		"sso_url": redirectURL.String(),
		"session": session,
	})
}

func (h *Handler) EnterpriseSSOCallback(c fiber.Ctx) error {
	samlResponse := c.FormValue("SAMLResponse")
	relayState := c.FormValue("RelayState")

	if samlResponse == "" {
		return handler.SendBadRequest(c, nil, "SAMLResponse is required")
	}

	deployment := handler.GetDeployment(c)

	attemptID, redirectURI, err := decodeRelayState(relayState, deployment.ID)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid RelayState")
	}

	var attempt model.SignInAttempt
	if err := database.Connection.Where("id = ?", attemptID).First(&attempt).Error; err != nil {
		return handler.SendBadRequest(c, nil, "Invalid or expired authentication attempt")
	}

	if attempt.Completed {
		return handler.SendBadRequest(c, nil, "Authentication attempt already completed")
	}

	var session model.Session
	if err := database.Connection.Where("id = ?", attempt.SessionID).
		Preload("Signins").
		Preload("SigninAttempts").
		First(&session).Error; err != nil {
		return handler.SendBadRequest(c, nil, "Session not found")
	}

	if time.Since(attempt.CreatedAt) > 10*time.Minute {
		return handler.SendBadRequest(c, nil, "Authentication attempt has expired")
	}

	if attempt.EnterpriseConnectionID == nil {
		return handler.SendBadRequest(c, nil, "Invalid sign-in attempt")
	}

	ssoService := service.NewSSOService()
	connection, err := ssoService.GetConnectionByID(*attempt.EnterpriseConnectionID)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid enterprise connection")
	}

	if connection.Domain == nil || !connection.Domain.Verified {
		return handler.SendBadRequest(c, nil, "Enterprise connection is not bound to a verified domain")
	}

	var keypair model.DeploymentKeyPair
	if err := database.Connection.Where("deployment_id = ?", deployment.ID).First(&keypair).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to get deployment keypair")
	}

	var requestIDs []string
	if attempt.SamlRequestID != nil && *attempt.SamlRequestID != "" {
		requestIDs = []string{*attempt.SamlRequestID}
	}

	assertion, err := validateSAMLResponse(connection, samlResponse, &deployment, keypair, requestIDs)
	if err != nil {
		return handler.SendBadRequest(c, nil, fmt.Sprintf("Invalid SAML response: %v", err))
	}

	userEmail := strings.ToLower(assertion.Subject.NameID.Value)
	if userEmail == "" {
		return handler.SendBadRequest(c, nil, "No email found in SAML assertion")
	}

	if !emailMatchesConnectionDomain(userEmail, connection) {
		return handler.SendBadRequest(c, nil, "Email domain does not match the verified domain bound to this enterprise connection")
	}

	var user *model.User
	var created bool

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		var lockedAttempt model.SignInAttempt
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ?", attempt.ID).
			First(&lockedAttempt).Error; err != nil {
			return err
		}
		if lockedAttempt.Completed {
			return errAttemptAlreadyCompleted
		}

		var email model.UserEmailAddress
		err := tx.Where("email_address = ? AND deployment_id = ?", userEmail, deployment.ID).
			Preload("User").
			First(&email).Error

		if err == gorm.ErrRecordNotFound {
			// Check if JIT provisioning is enabled for this connection
			if !connection.JitEnabled {
				return fmt.Errorf("user not found and JIT provisioning is disabled - please contact your administrator")
			}
			user, err = h.createSSOUser(tx, userEmail, assertion, &deployment, connection)
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
		if err := tx.Save(&attempt).Error; err != nil {
			return err
		}

		utils.PublishWebhookEvent(deployment.ID, "session.created", session.ID, "session")

		if created {
			utils.PublishSignUpEvent(deployment.ID, user, "enterprise_sso", &userEmail, signIn, c)
		}
		utils.PublishSignInEvent(deployment.ID, user, "enterprise_sso", &userEmail, signIn, c)

		return nil
	})

	if err != nil {
		if errors.Is(err, errAttemptAlreadyCompleted) {
			return handler.SendBadRequest(c, nil, "Authentication attempt already completed")
		}
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
		return handler.SendInternalServerError(c, err, "Failed to complete SSO authentication")
	}

	h.service.TrackMAU(deployment.ID, user.ID)
	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	if redirectURI != "" {
		if err := validateSSORedirectURI(&deployment, redirectURI); err != nil {
			redirectURI = ""
		}
	}
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

func (h *Handler) createSSOUser(
	tx *gorm.DB,
	email string,
	assertion *saml.Assertion,
	deployment *model.Deployment,
	connection *model.EnterpriseConnection,
) (*model.User, error) {
	primaryAddressID := idgen.NextID()

	firstNameAttrs := []string{"firstname", "first_name", "givenname"}
	lastNameAttrs := []string{"lastname", "last_name", "surname", "familyname"}

	if connection != nil && connection.AttributeMapping != nil {
		if customFirstName, ok := connection.AttributeMapping["first_name"].(string); ok && customFirstName != "" {
			firstNameAttrs = []string{strings.ToLower(customFirstName)}
		}
		if customLastName, ok := connection.AttributeMapping["last_name"].(string); ok && customLastName != "" {
			lastNameAttrs = []string{strings.ToLower(customLastName)}
		}
	}

	firstName := ""
	lastName := ""
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			attrNameLower := strings.ToLower(attr.Name)
			for _, fn := range firstNameAttrs {
				if attrNameLower == fn {
					if len(attr.Values) > 0 {
						firstName = attr.Values[0].Value
					}
					break
				}
			}
			for _, ln := range lastNameAttrs {
				if attrNameLower == ln {
					if len(attr.Values) > 0 {
						lastName = attr.Values[0].Value
					}
					break
				}
			}
		}
	}

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

func buildServiceProvider(
	connection *model.EnterpriseConnection,
	deployment *model.Deployment,
	keypair model.DeploymentKeyPair,
) (*saml.ServiceProvider, error) {
	if keypair.SamlPrivateKey == nil {
		return nil, fmt.Errorf("SAML private key not configured")
	}

	keyBlock, _ := pem.Decode([]byte(*keypair.SamlPrivateKey))
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to parse SAML private key PEM")
	}

	var privKey *rsa.PrivateKey
	pk, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		privKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse SAML private key: %v", err)
		}
	} else {
		var ok bool
		privKey, ok = pk.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("SAML private key is not RSA")
		}
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{deployment.BackendHost},
			CommonName:   deployment.BackendHost,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create SAML certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SAML certificate: %v", err)
	}

	idpCertBlock, _ := pem.Decode([]byte(connection.IdpCertificate))
	if idpCertBlock == nil {
		return nil, fmt.Errorf("failed to parse IdP certificate PEM")
	}
	idpCert, err := x509.ParseCertificate(idpCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IdP certificate: %v", err)
	}

	acsURL, _ := url.Parse(fmt.Sprintf("https://%s/auth/sso/callback", deployment.BackendHost))
	metadataURL, _ := url.Parse(fmt.Sprintf("https://%s/auth/sso/metadata", deployment.BackendHost))
	idpSSOURL, _ := url.Parse(connection.IdpSSOURL)

	sp := &saml.ServiceProvider{
		Key:         privKey,
		Certificate: cert,
		MetadataURL: *metadataURL,
		AcsURL:      *acsURL,
		IDPMetadata: &saml.EntityDescriptor{
			EntityID: connection.IdpEntityID,
			IDPSSODescriptors: []saml.IDPSSODescriptor{{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{
						KeyDescriptors: []saml.KeyDescriptor{{
							Use: "signing",
							KeyInfo: saml.KeyInfo{
								X509Data: saml.X509Data{
									X509Certificates: []saml.X509Certificate{{
										Data: base64.StdEncoding.EncodeToString(idpCert.Raw),
									}},
								},
							},
						}},
					},
				},
				SingleSignOnServices: []saml.Endpoint{{
					Binding:  saml.HTTPRedirectBinding,
					Location: idpSSOURL.String(),
				}},
			}},
		},
	}

	return sp, nil
}

func validateSAMLResponse(
	connection *model.EnterpriseConnection,
	samlResponseB64 string,
	deployment *model.Deployment,
	keypair model.DeploymentKeyPair,
	requestIDs []string,
) (*saml.Assertion, error) {
	sp, err := buildServiceProvider(connection, deployment, keypair)
	if err != nil {
		return nil, err
	}

	samlResponseXML, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SAMLResponse: %v", err)
	}

	acsURL, _ := url.Parse(fmt.Sprintf("https://%s/auth/sso/callback", deployment.BackendHost))
	assertion, err := sp.ParseXMLResponse(samlResponseXML, requestIDs, *acsURL)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %v", err)
	}

	return assertion, nil
}

func emailMatchesConnectionDomain(email string, connection *model.EnterpriseConnection) bool {
	if connection == nil || connection.Domain == nil || !connection.Domain.Verified {
		return false
	}
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return false
	}
	emailDomain := strings.ToLower(strings.TrimSpace(email[at+1:]))
	connectionDomain := strings.ToLower(strings.TrimSpace(connection.Domain.Fqdn))
	return emailDomain != "" && emailDomain == connectionDomain
}

func validateSSORedirectURI(deployment *model.Deployment, redirectURI string) error {
	value := strings.TrimSpace(redirectURI)
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return fmt.Errorf("redirect_uri must be an absolute URL")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && scheme != "http" {
		return fmt.Errorf("redirect_uri must use http or https")
	}

	if deployment == nil || !deployment.IsProduction() {
		return nil
	}
	if scheme != "https" {
		return fmt.Errorf("redirect_uri must use https in production")
	}
	if deployment.FrontendHost == "" {
		return fmt.Errorf("deployment frontend host is not configured")
	}

	redirectHost := strings.ToLower(parsed.Hostname())
	frontendHost := strings.ToLower(strings.TrimSpace(deployment.FrontendHost))
	if i := strings.IndexByte(frontendHost, '/'); i >= 0 {
		frontendHost = frontendHost[:i]
	}
	if h, _, splitErr := net.SplitHostPort(frontendHost); splitErr == nil {
		frontendHost = h
	}
	if redirectHost == frontendHost {
		return nil
	}
	frontendSite, fErr := publicsuffix.EffectiveTLDPlusOne(frontendHost)
	redirectSite, rErr := publicsuffix.EffectiveTLDPlusOne(redirectHost)
	if fErr != nil || rErr != nil {
		return fmt.Errorf("redirect_uri host must match deployment frontend domain")
	}
	if strings.EqualFold(frontendSite, redirectSite) {
		return nil
	}
	return fmt.Errorf("redirect_uri host must match deployment frontend domain")
}

func encodeRelayState(attemptID uint64, redirectURI string, deploymentID uint64) string {
	data := fmt.Sprintf("%d|%s|%d", attemptID, redirectURI, deploymentID)
	return base64.URLEncoding.EncodeToString([]byte(data))
}

func decodeRelayState(relayState string, expectedDeploymentID uint64) (uint64, string, error) {
	if relayState == "" {
		return 0, "", fmt.Errorf("empty relay state")
	}

	data, err := base64.URLEncoding.DecodeString(relayState)
	if err != nil {
		return 0, "", fmt.Errorf("failed to decode relay state: %v", err)
	}

	parts := strings.SplitN(string(data), "|", 3)
	if len(parts) != 3 {
		return 0, "", fmt.Errorf("invalid relay state format")
	}

	attemptID, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("invalid attempt ID in relay state")
	}

	redirectURI := parts[1]

	deploymentID, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("invalid deployment ID in relay state")
	}

	if deploymentID != expectedDeploymentID {
		return 0, "", fmt.Errorf("deployment ID mismatch in relay state")
	}

	return attemptID, redirectURI, nil
}

func (h *Handler) SSOMetadata(c fiber.Ctx) error {
	deployment := handler.GetDeployment(c)

	var keypair model.DeploymentKeyPair
	if err := database.Connection.Where("deployment_id = ?", deployment.ID).First(&keypair).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to get deployment keypair")
	}

	keyBlock, _ := pem.Decode([]byte(*keypair.SamlPrivateKey))
	if keyBlock == nil {
		return handler.SendInternalServerError(c, nil, "Failed to parse SAML private key PEM")
	}

	var privKey *rsa.PrivateKey
	pk, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		privKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return handler.SendInternalServerError(c, err, "Failed to parse SAML private key")
		}
	} else {
		var ok bool
		privKey, ok = pk.(*rsa.PrivateKey)
		if !ok {
			return handler.SendInternalServerError(c, nil, "SAML private key is not RSA")
		}
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{deployment.BackendHost},
			CommonName:   deployment.BackendHost,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create SAML certificate")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to parse SAML certificate")
	}

	acsURL, _ := url.Parse(fmt.Sprintf("https://%s/auth/sso/callback", deployment.BackendHost))
	metadataURL, _ := url.Parse(fmt.Sprintf("https://%s/auth/sso/metadata", deployment.BackendHost))
	entityID := fmt.Sprintf("https://%s", deployment.BackendHost)

	sp := &saml.ServiceProvider{
		Key:         privKey,
		Certificate: cert,
		MetadataURL: *metadataURL,
		AcsURL:      *acsURL,
		EntityID:    entityID,
	}

	metadata := sp.Metadata()

	c.Set("Content-Type", "application/xml")
	c.Set("Content-Disposition", "inline; filename=\"sp-metadata.xml\"")

	xmlBytes, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to generate metadata XML")
	}

	return c.Send(append([]byte(xml.Header), xmlBytes...))
}
