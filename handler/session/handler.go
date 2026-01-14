package session

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"maps"
	"slices"
	"strconv"
	"time"

	"github.com/aymerick/raymond"
	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/service"
	"github.com/ilabs/wacht-fe/utils"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"gorm.io/gorm"
)

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) GetCurrentSession(
	c *fiber.Ctx,
) error {
	session := handler.GetSession(c)

	return handler.SendSuccess(c, session)
}

func (h *Handler) SwitchActiveSignIn(
	c *fiber.Ctx,
) error {
	session := handler.GetSession(c)

	signInId, err := strconv.ParseUint(c.Query("sign_in_id"), 10, 64)

	if err != nil {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"Invalid sign in ID",
		)
	}

	validSignIn := false
	for _, signIn := range session.Signins {
		if signIn.ID == signInId {
			session.ActiveSignin = &signIn
			validSignIn = true
			break
		}
	}

	if !validSignIn {
		return fiber.NewError(
			fiber.StatusBadRequest,
			"Invalid sign in ID",
		)
	}

	session.ActiveSigninID = &signInId

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	database.Connection.Model(&model.Session{}).Where("id = ?", session.ID).Updates(map[string]interface{}{
		"active_signin_id": session.ActiveSigninID,
	})
	return handler.SendSuccess(c, session)
}

func (h *Handler) SignOut(
	c *fiber.Ctx,
) error {
	session := handler.GetSession(
		c,
	)

	signInIdStr := c.Query(
		"sign_in_id",
	)

	if signInIdStr != "" {
		signInId, err := strconv.ParseUint(signInIdStr, 10, 64)
		if err != nil {
			return fiber.NewError(
				fiber.StatusBadRequest,
				"Invalid sign in ID",
			)
		}

		signIn := new(
			model.Signin,
		)
		count := database.Connection.Where("id = ? AND session_id = ?", signInId, session.ID).
			First(signIn).
			RowsAffected

		if count == 0 {
			return fiber.NewError(
				fiber.StatusBadRequest,
				"Sign in not found",
			)
		}

		deployment := handler.GetDeployment(c)
		utils.PublishWebhookEvent(deployment.ID, "session.deleted", session.ID, "session")

		err = database.Connection.Transaction(
			func(tx *gorm.DB) error {
				tx.Delete(signIn)
				tx.Model(&model.Session{}).Where("id = ?", session.ID).Update("active_signin_id", nil)
				return nil
			},
		)
		if err != nil {
			return handler.SendInternalServerError(
				c,
				nil,
				"Failed to sign out",
			)
		}

		handler.RemoveSessionFromCacheAndLocals(
			c,
			session.ID,
		)
		return handler.SendSuccess(
			c,
			session,
		)
	} else {
		deployment := handler.GetDeployment(c)
		if session.ActiveSignin != nil {
			utils.PublishWebhookEvent(deployment.ID, "session.deleted", session.ID, "session")
		}

		err := database.Connection.Transaction(func(tx *gorm.DB) error {
			tx.Model(&model.Session{}).Where("id = ?", session.ID).Update("active_signin_id", nil)
			tx.Where("session_id = ?", session.ID).Delete(&model.Signin{})
			return nil
		})
		if err != nil {
			return handler.SendInternalServerError(c, nil, "Failed to sign out")
		}

		handler.RemoveSessionFromCacheAndLocals(c, session.ID)
		return handler.SendSuccess(c, session)
	}
}

func (h *Handler) SwitchOrganization(
	c *fiber.Ctx,
) error {
	session := handler.GetSession(c)
	orgID := c.Query("organization_id")

	if session.ActiveSignin == nil {
		return fiber.NewError(fiber.StatusBadRequest, "No active sign in")
	}

	if orgID == "" {
		tx := database.Connection.Begin()
		if err := tx.Model(&model.User{}).Where("id = ?", session.ActiveSignin.UserID).
			Updates(map[string]any{
				"active_organization_membership_id": nil,
				"active_workspace_membership_id":    nil,
			}).Error; err != nil {
			tx.Rollback()
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to update user")
		}
		if err := tx.Model(&model.Signin{}).Where("id = ?", session.ActiveSignin.ID).
			Updates(map[string]any{
				"active_organization_membership_id": nil,
				"active_workspace_membership_id":    nil,
			}).Error; err != nil {
			tx.Rollback()
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to update signin")
		}
		tx.Commit()
		handler.RemoveSessionFromCacheAndLocals(c, session.ID)
		return handler.SendSuccess(c, session)
	}

	orgIDuint64, err := strconv.ParseUint(orgID, 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid org ID")
	}

	membership := new(model.OrganizationMembership)
	if err := database.Connection.
		Preload("Roles").
		Model(&model.OrganizationMembership{}).
		Where("user_id = ? AND organization_id = ?", session.ActiveSignin.UserID, orgIDuint64).
		First(membership).Error; err != nil || membership.ID == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "You are not a member of this organization")
	}

	var org model.Organization
	if err := database.Connection.First(&org, orgIDuint64).Error; err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to load organization")
	}

	var user model.User
	if err := database.Connection.Preload("UserAuthenticator").First(&user, session.ActiveSignin.UserID).Error; err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to load user")
	}

	deployment := handler.GetDeployment(c)
	orgData := model.PublicOrganizationData{
		WhitelistedIPs:      org.WhitelistedIPs,
		EnforceMFASetup:     org.EnforceMFASetup,
		EnableIPRestriction: org.EnableIPRestriction,
	}

	eligibility := utils.CalculateOrganizationEligibility(
		&user,
		&orgData,
		membership.Roles,
		c.IP(),
		&deployment,
	)

	if eligibility.Type != model.EligibilityRestrictionNone {
		return fiber.NewError(fiber.StatusForbidden, eligibility.Message)
	}

	tx := database.Connection.Begin()
	if err := tx.Model(&model.User{}).Where("id = ?", session.ActiveSignin.UserID).
		Updates(map[string]interface{}{
			"active_organization_membership_id": membership.ID,
			"active_workspace_membership_id":    nil,
		}).Error; err != nil {
		tx.Rollback()
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to update user")
	}
	if err := tx.Model(&model.Signin{}).Where("id = ?", session.ActiveSignin.ID).
		Updates(map[string]interface{}{
			"active_organization_membership_id": membership.ID,
			"active_workspace_membership_id":    nil,
		}).Error; err != nil {
		tx.Rollback()
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to update signin")
	}
	tx.Commit()
	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	natsService := service.GetNATS()
	go natsService.PublishBillingEvent(deployment.ID, orgIDuint64, "organization_accessed")

	return handler.SendSuccess(c, session)
}

func (h *Handler) SwitchWorkspace(
	c *fiber.Ctx,
) error {
	session := handler.GetSession(c)
	workspaceID := c.Query("workspace_id")

	if session.ActiveSignin == nil {
		return fiber.NewError(fiber.StatusBadRequest, "No active sign in")
	}

	if workspaceID == "" {
		// Use a transaction for atomicity
		tx := database.Connection.Begin()
		if err := tx.Model(&model.User{}).Where("id = ?", session.ActiveSignin.UserID).
			Updates(map[string]interface{}{
				"active_workspace_membership_id":    nil,
				"active_organization_membership_id": nil,
			}).Error; err != nil {
			tx.Rollback()
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to update user")
		}
		if err := tx.Model(&model.Signin{}).Where("id = ?", session.ActiveSignin.ID).
			Updates(map[string]interface{}{
				"active_workspace_membership_id":    nil,
				"active_organization_membership_id": nil,
			}).Error; err != nil {
			tx.Rollback()
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to update signin")
		}
		tx.Commit()
		handler.RemoveSessionFromCacheAndLocals(c, session.ID)
		return handler.SendSuccess(c, session)
	}

	workspaceIDuint64, err := strconv.ParseUint(workspaceID, 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid workspace ID")
	}

	membership := new(model.WorkspaceMembership)
	if err := database.Connection.
		Preload("Roles").
		Model(&model.WorkspaceMembership{}).
		Where("user_id = ? AND workspace_id = ?", session.ActiveSignin.UserID, workspaceIDuint64).
		Joins("Organization").
		First(membership).Error; err != nil {
		log.Println(err)
		return fiber.NewError(fiber.StatusBadRequest, "You are not a member of this workspace")
	}

	// Load workspace details
	var workspace model.Workspace
	if err := database.Connection.First(&workspace, workspaceIDuint64).Error; err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to load workspace")
	}

	// Load user with MFA details
	var user model.User
	if err := database.Connection.Preload("UserAuthenticator").First(&user, session.ActiveSignin.UserID).Error; err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to load user")
	}

	// Check eligibility before allowing switch
	deployment := handler.GetDeployment(c)
	workspaceData := model.PublicWorkspaceData{
		WhitelistedIPs:      workspace.WhitelistedIPs,
		EnforceMFASetup:     workspace.EnforceMFASetup,
		EnableIPRestriction: workspace.EnableIPRestriction,
	}

	eligibility := utils.CalculateWorkspaceEligibility(
		&user,
		&workspaceData,
		membership.Roles,
		c.IP(),
		&deployment,
	)

	if eligibility.Type != model.EligibilityRestrictionNone {
		return fiber.NewError(fiber.StatusForbidden, eligibility.Message)
	}

	tx := database.Connection.Begin()
	if err := tx.Model(&model.User{}).Where("id = ?", session.ActiveSignin.UserID).
		Updates(map[string]interface{}{
			"active_workspace_membership_id":    membership.ID,
			"active_organization_membership_id": membership.OrganizationMembershipID,
		}).Error; err != nil {
		tx.Rollback()
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to update user")
	}
	if err := tx.Model(&model.Signin{}).Where("id = ?", session.ActiveSignin.ID).
		Updates(map[string]interface{}{
			"active_workspace_membership_id":    membership.ID,
			"active_organization_membership_id": membership.OrganizationMembershipID,
		}).Error; err != nil {
		tx.Rollback()
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to update signin")
	}
	tx.Commit()
	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	deployment = handler.GetDeployment(c)
	natsService := service.GetNATS()
	go natsService.PublishBillingEvent(deployment.ID, workspaceIDuint64, "workspace_accessed")

	return handler.SendSuccess(c, session)
}

func (h *Handler) GetToken(
	c *fiber.Ctx,
) error {
	deployment := handler.GetDeployment(c)
	deployment.LoadPrivateKey(database.Connection)
	templatename := c.Query("template", "default")

	template := new(model.DeploymentJwtTemplate)

	if templatename != "default" {
		if database.Connection.
			Model(&model.DeploymentJwtTemplate{}).
			Where("name = ? AND deployment_id = ?", templatename, deployment.ID).
			First(template).
			Error != nil {
			return handler.SendNotFound(c, nil, "Template not found")
		}
	} else {
		template.Name = "default"
		template.AllowedClockSkew = 5
		template.TokenLifetime = 30
	}

	sessionId := c.Locals("session").(uint64)
	session, err := utils.GetSessionByID(sessionId)
	if err != nil {
		return handler.SendNotFound(c, nil, "Session not found")
	}

	if session.ActiveSignin == nil {
		return handler.SendBadRequest(c, nil, "No active sign in")
	}

	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(fmt.Sprintf("https://%s", deployment.BackendHost)).
		Subject(strconv.FormatUint(*session.ActiveSignin.UserID, 10)).
		IssuedAt(now).
		Expiration(now.Add(time.Duration(template.TokenLifetime+template.AllowedClockSkew) * time.Second)).
		Build()

	if err != nil {
		log.Println("Error building JWT token:", err)
		return handler.SendInternalServerError(c, nil, "Failed to generate token")
	}

	tok.Set("session_id", strconv.FormatUint(session.ID, 10))
	tok.Set("sid", strconv.FormatUint(session.ID, 10))

	tokenPermissions := map[string][]string{}

	log.Println("here", session.ActiveSignin.ActiveOrganizationMembership)

	if session.ActiveSignin.ActiveOrganizationMembership != nil {
		permissionsMap := map[string]bool{}
		for _, role := range session.ActiveSignin.ActiveOrganizationMembership.Roles {
			for _, rolepermissions := range role.Permissions {
				permissionsMap[rolepermissions] = true
			}
		}
		permissions := slices.Collect(maps.Keys(permissionsMap))
		tokenPermissions["organization"] = permissions
		tok.Set(
			"organization",
			strconv.FormatUint(session.ActiveSignin.ActiveOrganizationMembership.OrganizationID, 10),
		)
	}
	if session.ActiveSignin.ActiveWorkspaceMembership != nil {
		permissionsMap := map[string]bool{}
		for _, role := range session.ActiveSignin.ActiveWorkspaceMembership.Roles {
			for _, rolepermissions := range role.Permissions {
				permissionsMap[rolepermissions] = true
			}
		}
		permissions := slices.Collect(maps.Keys(permissionsMap))
		tokenPermissions["workspace"] = permissions
		tok.Set("workspace", strconv.FormatUint(session.ActiveSignin.ActiveWorkspaceMembership.WorkspaceID, 10))
	}

	tok.Set("permissions", tokenPermissions)

	signingAlg := template.CustomSigningKey.Algorithm
	secret := template.CustomSigningKey.Key
	if signingAlg == "" {
		signingAlg = "ES256"
	}

	if secret == "" {
		secret = deployment.KepPair.PrivateKey
	}

	metadataRaw := string(template.Template)
	if metadataRaw == "" {
		metadataRaw = "{}"
	}

	stralizedsignin, _ := json.Marshal(session.ActiveSignin)
	parsed := new(map[string]any)
	json.Unmarshal(stralizedsignin, parsed)

	metadataPopulated, err := raymond.Render(metadataRaw, parsed)

	if err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to render metadata")
	}

	metadataJson := new(map[string]any)
	err = json.Unmarshal([]byte(metadataPopulated), metadataJson)
	if err != nil {
		log.Println(err)
		return handler.SendInternalServerError(c, nil, "Failed to unmarshal metadata")
	}

	if len(*metadataJson) != 0 {
		tok.Set("metadata", metadataJson)
	}

	signedToken, err := signToken(tok, signingAlg, secret)
	if err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to sign token")
	}

	return handler.SendSuccess(c, fiber.Map{
		"token":   signedToken,
		"expires": time.Now().Add(time.Duration(template.TokenLifetime) * time.Second).UnixMilli(),
	})
}

func signToken(tok jwt.Token, alg string, secret string) (string, error) {
	switch alg {
	case "HS256":
		return signTokenHS256(tok, secret)
	case "HS384":
		return signTokenHS384(tok, secret)
	case "HS512":
		return signTokenHS512(tok, secret)
	case "RS256":
		return signTokenRS256(tok, secret)
	case "RS384":
		return signTokenRS384(tok, secret)
	case "RS512":
		return signTokenRS512(tok, secret)
	case "ES256":
		return signTokenES256(tok, secret)
	case "ES384":
		return signTokenES384(tok, secret)
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

func signTokenHS256(tok jwt.Token, secret string) (string, error) {
	key := []byte(secret)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), key))
	if err != nil {
		return "", fmt.Errorf("failed to sign with HS256: %w", err)
	}
	return string(signed), nil
}

func signTokenHS384(tok jwt.Token, secret string) (string, error) {
	key := []byte(secret)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS384(), key))
	if err != nil {
		return "", fmt.Errorf("failed to sign with HS384: %w", err)
	}
	return string(signed), nil
}

func signTokenHS512(tok jwt.Token, secret string) (string, error) {
	key := []byte(secret)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS512(), key))
	if err != nil {
		return "", fmt.Errorf("failed to sign with HS512: %w", err)
	}
	return string(signed), nil
}

func signTokenRS256(tok jwt.Token, privateKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format if PKCS1 fails
		pk, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return "", fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		privateKey, ok = pk.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("not an RSA private key")
		}
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign with RS256: %w", err)
	}
	return string(signed), nil
}

func signTokenRS384(tok jwt.Token, privateKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format if PKCS1 fails
		pk, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return "", fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		privateKey, ok = pk.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("not an RSA private key")
		}
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS384(), privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign with RS384: %w", err)
	}
	return string(signed), nil
}

func signTokenRS512(tok jwt.Token, privateKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format if PKCS1 fails
		pk, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return "", fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		privateKey, ok = pk.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("not an RSA private key")
		}
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS512(), privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign with RS512: %w", err)
	}
	return string(signed), nil
}

func signTokenES256(tok jwt.Token, privateKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block containing private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format if direct parsing fails
		pk, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return "", fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		privateKey, ok = pk.(*ecdsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("not an ECDSA private key")
		}
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign with ES256: %w", err)
	}
	return string(signed), nil
}

func signTokenES384(tok jwt.Token, privateKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block containing private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format if direct parsing fails
		pk, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return "", fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		privateKey, ok = pk.(*ecdsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("not an ECDSA private key")
		}
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES384(), privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign with ES384: %w", err)
	}
	return string(signed), nil
}
