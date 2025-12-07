package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"log"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/godruoyi/go-snowflake"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/service"
	"github.com/ilabs/wacht-fe/utils"
	"gorm.io/gorm"
)

func (h *Handler) SSOLogin(c *fiber.Ctx) error {
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

	ssoService := service.NewSSOService()
	connection, err := ssoService.GetConnectionByID(connectionID)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid enterprise connection")
	}

	if connection.DeploymentID != deployment.ID {
		return handler.SendBadRequest(c, nil, "Invalid enterprise connection for this deployment")
	}

	var keypair model.DeploymentKeyPair
	if err := database.Connection.Where("deployment_id = ?", deployment.ID).First(&keypair).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to get deployment keypair")
	}

	attempt := model.NewSignInAttempt(model.SignInMethodEnterpriseSso)
	attempt.SessionID = session.ID
	attempt.EnterpriseConnectionID = &connection.ID

	if err := database.Connection.Create(attempt).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create sign-in attempt")
	}

	sp, err := buildServiceProvider(connection, &deployment, keypair)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to build SAML service provider")
	}

	authnRequest, _ := sp.MakeAuthenticationRequest(connection.IdpSSOURL, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	relayState := encodeRelayState(attempt.ID, redirectURI, deployment.ID)
	redirectURL, _ := authnRequest.Redirect(relayState, sp)

	return handler.SendSuccess(c, fiber.Map{
		"sso_url": redirectURL.String(),
		"session": session,
	})
}

func (h *Handler) EnterpriseSSOCallback(c *fiber.Ctx) error {
	samlResponse := c.FormValue("SAMLResponse")
	relayState := c.FormValue("RelayState")

	log.Printf("[SSO Callback] SAMLResponse length: %d, RelayState: %s", len(samlResponse), relayState)

	if samlResponse == "" {
		return handler.SendBadRequest(c, nil, "SAMLResponse is required")
	}

	deployment := handler.GetDeployment(c)

	attemptID, redirectURI, err := decodeRelayState(relayState, deployment.ID)
	if err != nil {
		log.Printf("[SSO Callback] Failed to decode RelayState: %v", err)
		return handler.SendBadRequest(c, nil, "Invalid RelayState")
	}

	log.Printf("[SSO Callback] Decoded attemptID: %d, redirectURI: %s", attemptID, redirectURI)

	// Lookup attempt by ID from RelayState (not by session)
	var attempt model.SignInAttempt
	if err := database.Connection.Where("id = ?", attemptID).First(&attempt).Error; err != nil {
		log.Printf("[SSO Callback] Failed to find attempt with ID %d: %v", attemptID, err)
		return handler.SendBadRequest(c, nil, "Invalid or expired authentication attempt")
	}

	log.Printf("[SSO Callback] Found attempt: ID=%d, SessionID=%d, CreatedAt=%v, ConnectionID=%v",
		attempt.ID, attempt.SessionID, attempt.CreatedAt, attempt.EnterpriseConnectionID)

	// Load the original session from the attempt
	var session model.Session
	if err := database.Connection.Where("id = ?", attempt.SessionID).
		Preload("Signins").
		Preload("SigninAttempts").
		First(&session).Error; err != nil {
		log.Printf("[SSO Callback] Failed to find session with ID %d: %v", attempt.SessionID, err)
		return handler.SendBadRequest(c, nil, "Session not found")
	}

	log.Printf("[SSO Callback] Found session: ID=%d, AttemptAge=%v", session.ID, time.Since(attempt.CreatedAt))

	if time.Since(attempt.CreatedAt) > 10*time.Minute {
		log.Printf("[SSO Callback] Attempt expired! CreatedAt=%v, Now=%v, Age=%v",
			attempt.CreatedAt, time.Now(), time.Since(attempt.CreatedAt))
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

	var keypair model.DeploymentKeyPair
	if err := database.Connection.Where("deployment_id = ?", deployment.ID).First(&keypair).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to get deployment keypair")
	}

	assertion, err := validateSAMLResponse(connection, samlResponse, &deployment, keypair)
	if err != nil {
		return handler.SendBadRequest(c, nil, fmt.Sprintf("Invalid SAML response: %v", err))
	}

	userEmail := strings.ToLower(assertion.Subject.NameID.Value)
	if userEmail == "" {
		return handler.SendBadRequest(c, nil, "No email found in SAML assertion")
	}

	var user *model.User
	var created bool

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		var email model.UserEmailAddress
		err := tx.Where("email_address = ? AND deployment_id = ?", userEmail, deployment.ID).
			Preload("User").
			First(&email).Error

		if err == gorm.ErrRecordNotFound {
			user, err = h.createSSOUser(tx, userEmail, assertion, connection, &deployment)
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

		signIn := h.service.CreateSignin(user.ID, session.ID, c, deployment.AuthSettings.SessionValidityPeriod)
		if err := tx.Create(signIn).Error; err != nil {
			return err
		}

		if err := tx.Model(&model.Session{}).Where("id = ?", session.ID).Update("active_signin_id", signIn.ID).Error; err != nil {
			return err
		}

		session.ActiveSigninID = &signIn.ID
		session.Signins = append(session.Signins, *signIn)

		attempt.Completed = true
		attempt.UserID = &user.ID
		attempt.FirstMethodAuthenticated = true
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
		return handler.SendInternalServerError(c, err, "Failed to complete SSO authentication")
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
		// For staging deployments, add session token to URL so frontend can store it
		if !deployment.IsProduction() {
			var keypair model.DeploymentKeyPair
			if err := database.Connection.Where("deployment_id = ?", deployment.ID).First(&keypair).Error; err == nil {
				token, err := utils.SignNewJWT(session.ID, deployment.BackendHost, time.Now().Add(6*time.Hour), keypair, database.Connection)
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

func (h *Handler) createSSOUser(
	tx *gorm.DB,
	email string,
	assertion *saml.Assertion,
	connection *model.EnterpriseConnection,
	deployment *model.Deployment,
) (*model.User, error) {
	primaryAddressID := snowflake.ID()

	firstName := ""
	lastName := ""
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			switch strings.ToLower(attr.Name) {
			case "firstname", "first_name", "givenname":
				if len(attr.Values) > 0 {
					firstName = attr.Values[0].Value
				}
			case "lastname", "last_name", "surname", "familyname":
				if len(attr.Values) > 0 {
					lastName = attr.Values[0].Value
				}
			}
		}
	}

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

func buildServiceProvider(
	connection *model.EnterpriseConnection,
	deployment *model.Deployment,
	keypair model.DeploymentKeyPair,
) (*saml.ServiceProvider, error) {
	// Use SAML RSA key (not ECDSA used for JWT)
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

	// Generate self-signed certificate from RSA key
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
	assertion, err := sp.ParseXMLResponse(samlResponseXML, []string{""}, *acsURL)
	if err != nil {
		return nil, err
	}

	return assertion, nil
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

func (h *Handler) SSOMetadata(c *fiber.Ctx) error {
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
