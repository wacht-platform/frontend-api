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
	"github.com/gofiber/fiber/v3"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/model"
	"github.com/wacht-platform/frontend-api/service"
	"github.com/wacht-platform/frontend-api/utils"
	"gorm.io/gorm"
)

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

type switchOrgCTEResult struct {
	EligibilityType string `gorm:"column:eligibility_type"`
	MembershipID    uint64 `gorm:"column:membership_id"`
}

type switchWorkspaceCTEResult struct {
	EligibilityType string `gorm:"column:eligibility_type"`
	MembershipID    uint64 `gorm:"column:membership_id"`
	OrgMembershipID uint64 `gorm:"column:org_membership_id"`
}

func (h *Handler) GetCurrentSession(
	c fiber.Ctx,
) error {
	session := handler.GetSession(c)

	return handler.SendSuccess(c, session)
}

func (h *Handler) SwitchActiveSignIn(
	c fiber.Ctx,
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
	c fiber.Ctx,
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
	c fiber.Ctx,
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

	deployment := handler.GetDeployment(c)
	var result switchOrgCTEResult

	rawSQL := `
		WITH member_info AS (
			SELECT
				om.id as membership_id,
				o.whitelisted_ips as org_ips,
				o.enforce_mfa_setup as org_mfa_setup,
				o.enable_ip_restriction as org_ip_restriction,
				(u.backup_codes_generated OR EXISTS(SELECT 1 FROM user_authenticators WHERE user_id = u.id)) as user_has_mfa,
				EXISTS (
					SELECT 1 FROM organization_membership_roles omr
					JOIN organization_roles orr ON omr.organization_role_id = orr.id
					WHERE omr.organization_membership_id = om.id AND orr.permissions @> ARRAY['organization:admin']
				) as is_admin
			FROM organization_memberships om
			JOIN organizations o ON om.organization_id = o.id
			JOIN users u ON om.user_id = u.id
			WHERE om.user_id = ? AND om.organization_id = ?
			LIMIT 1
		),
		eligibility AS (
			SELECT
				m.*,
				CASE
					WHEN m.is_admin THEN 'none'
					WHEN ? AND m.org_ip_restriction AND cardinality(m.org_ips) > 0 AND NOT (?::inet <<= ANY(m.org_ips::inet[]))
						 AND ? AND m.org_mfa_setup AND NOT m.user_has_mfa THEN 'ip_and_mfa_required'
					WHEN ? AND m.org_ip_restriction AND cardinality(m.org_ips) > 0 AND NOT (?::inet <<= ANY(m.org_ips::inet[])) THEN 'ip_not_allowed'
					WHEN ? AND m.org_mfa_setup AND NOT m.user_has_mfa THEN 'mfa_required'
					ELSE 'none'
				END as eligibility_type
			FROM member_info m
		),
		do_update_user AS (
			UPDATE users
			SET active_organization_membership_id = e.membership_id,
				active_workspace_membership_id = NULL
			FROM eligibility e
			WHERE users.id = ? AND e.eligibility_type = 'none'
		),
		do_update_signin AS (
			UPDATE signins
			SET active_organization_membership_id = e.membership_id,
				active_workspace_membership_id = NULL
			FROM eligibility e
			WHERE signins.id = ? AND e.eligibility_type = 'none'
		)
		SELECT eligibility_type, membership_id FROM eligibility;
	`

	err = database.Connection.Raw(rawSQL,
		session.ActiveSignin.UserID, orgIDuint64,
		deployment.B2BSettings.IpAllowlistPerOrgEnabled, c.IP(), deployment.B2BSettings.EnforceMfaPerOrgEnabled,
		deployment.B2BSettings.IpAllowlistPerOrgEnabled, c.IP(),
		deployment.B2BSettings.EnforceMfaPerOrgEnabled,
		session.ActiveSignin.UserID, session.ActiveSignin.ID,
	).Scan(&result).Error

	if err != nil || result.MembershipID == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "You are not a member of this organization")
	}

	if result.EligibilityType != "none" {
		var message string
		switch result.EligibilityType {
		case "ip_and_mfa_required":
			message = "You must connect from an allowed IP address and set up Multi-Factor Authentication to access this organization."
		case "ip_not_allowed":
			message = "You must connect from an allowed IP address to access this organization."
		case "mfa_required":
			message = "You must set up Multi-Factor Authentication to access this organization."
		}
		return fiber.NewError(fiber.StatusForbidden, message)
	}

	// Update session in memory
	session.ActiveSignin.ActiveOrganizationMembershipID = &result.MembershipID
	session.ActiveSignin.ActiveWorkspaceMembershipID = nil

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	natsService := service.GetNATS()
	go natsService.PublishBillingEvent(deployment.ID, orgIDuint64, "organization_accessed")

	return handler.SendSuccess(c, session)
}

func (h *Handler) SwitchWorkspace(
	c fiber.Ctx,
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

	deployment := handler.GetDeployment(c)
	var result switchWorkspaceCTEResult

	rawSQL := `
		WITH member_info AS (
			SELECT
				wm.id as membership_id,
				wm.organization_membership_id as org_membership_id,
				w.whitelisted_ips as ws_ips,
				w.enforce_mfa_setup as ws_mfa_setup,
				w.enable_ip_restriction as ws_ip_restriction,
				(u.backup_codes_generated OR EXISTS(SELECT 1 FROM user_authenticators WHERE user_id = u.id)) as user_has_mfa,
				EXISTS (
					SELECT 1 FROM workspace_membership_roles wmr
					JOIN workspace_roles wr ON wmr.workspace_role_id = wr.id
					WHERE wmr.workspace_membership_id = wm.id AND wr.permissions @> ARRAY['workspace:admin']
				) OR EXISTS (
					SELECT 1 FROM organization_membership_roles omr
					JOIN organization_roles orr ON omr.organization_role_id = orr.id
					WHERE omr.organization_membership_id = om.id AND orr.permissions @> ARRAY['organization:admin']
				) as is_admin
			FROM workspace_memberships wm
			JOIN workspaces w ON wm.workspace_id = w.id
			JOIN organization_memberships om ON wm.organization_membership_id = om.id
			JOIN users u ON wm.user_id = u.id
			WHERE wm.user_id = ? AND wm.workspace_id = ?
			LIMIT 1
		),
		eligibility AS (
			SELECT
				m.*,
				CASE
					WHEN m.is_admin THEN 'none'
					WHEN ? AND m.ws_ip_restriction AND cardinality(m.ws_ips) > 0 AND NOT (?::inet <<= ANY(m.ws_ips::inet[]))
						 AND ? AND m.ws_mfa_setup AND NOT m.user_has_mfa THEN 'ip_and_mfa_required'
					WHEN ? AND m.ws_ip_restriction AND cardinality(m.ws_ips) > 0 AND NOT (?::inet <<= ANY(m.ws_ips::inet[])) THEN 'ip_not_allowed'
					WHEN ? AND m.ws_mfa_setup AND NOT m.user_has_mfa THEN 'mfa_required'
					ELSE 'none'
				END as eligibility_type
			FROM member_info m
		),
		do_update_user AS (
			UPDATE users
			SET active_workspace_membership_id = e.membership_id,
				active_organization_membership_id = e.org_membership_id
			FROM eligibility e
			WHERE users.id = ? AND e.eligibility_type = 'none'
		),
		do_update_signin AS (
			UPDATE signins
			SET active_workspace_membership_id = e.membership_id,
				active_organization_membership_id = e.org_membership_id
			FROM eligibility e
			WHERE signins.id = ? AND e.eligibility_type = 'none'
		)
		SELECT eligibility_type, membership_id, org_membership_id FROM eligibility;
	`

	err = database.Connection.Raw(rawSQL,
		session.ActiveSignin.UserID, workspaceIDuint64,
		deployment.B2BSettings.IpAllowlistPerWorkspaceEnabled, c.IP(), deployment.B2BSettings.EnforceMfaPerWorkspaceEnabled,
		deployment.B2BSettings.IpAllowlistPerWorkspaceEnabled, c.IP(),
		deployment.B2BSettings.EnforceMfaPerWorkspaceEnabled,
		session.ActiveSignin.UserID, session.ActiveSignin.ID,
	).Scan(&result).Error

	if err != nil || result.MembershipID == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "You are not a member of this workspace")
	}

	if result.EligibilityType != "none" {
		var message string
		switch result.EligibilityType {
		case "ip_and_mfa_required":
			message = "You must connect from an allowed IP address and set up Multi-Factor Authentication to access this workspace."
		case "ip_not_allowed":
			message = "You must connect from an allowed IP address to access this workspace."
		case "mfa_required":
			message = "You must set up Multi-Factor Authentication to access this workspace."
		}
		return fiber.NewError(fiber.StatusForbidden, message)
	}

	// Update session in memory
	session.ActiveSignin.ActiveWorkspaceMembershipID = &result.MembershipID
	session.ActiveSignin.ActiveOrganizationMembershipID = &result.OrgMembershipID

	handler.RemoveSessionFromCacheAndLocals(c, session.ID)

	natsService := service.GetNATS()
	go natsService.PublishBillingEvent(deployment.ID, workspaceIDuint64, "workspace_accessed")

	return handler.SendSuccess(c, session)
}

func (h *Handler) GetToken(
	c fiber.Ctx,
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

	sessionId := c.Locals("session")
	if sessionId == nil {
		return handler.SendNotFound(c, nil, "Session not found")
	}
	session, err := utils.GetSessionByID(sessionId.(uint64))
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

	tok.Set("sid", strconv.FormatUint(session.ID, 10))

	tokenPermissions := map[string][]string{}

	if session.ActiveSignin.ActiveOrganizationMembership != nil {
		permissionsMap := map[string]bool{}
		for _, role := range session.ActiveSignin.ActiveOrganizationMembership.Roles {
			for _, rolepermissions := range role.Permissions {
				permissionsMap[rolepermissions] = true
			}
		}
		permissions := slices.Collect(maps.Keys(permissionsMap))
		tokenPermissions["organization"] = permissions

		organizationID := session.ActiveSignin.ActiveOrganizationMembership.OrganizationID
		if organizationID == 0 && session.ActiveSignin.ActiveOrganizationMembership.Organization != nil {
			organizationID = session.ActiveSignin.ActiveOrganizationMembership.Organization.ID
		}

		if organizationID != 0 {
			tok.Set("organization", strconv.FormatUint(organizationID, 10))
		}
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

		workspaceID := session.ActiveSignin.ActiveWorkspaceMembership.WorkspaceID
		if workspaceID == 0 && session.ActiveSignin.ActiveWorkspaceMembership.Workspace != nil {
			workspaceID = session.ActiveSignin.ActiveWorkspaceMembership.Workspace.ID
		}

		if workspaceID != 0 {
			tok.Set("workspace", strconv.FormatUint(workspaceID, 10))
		}
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
