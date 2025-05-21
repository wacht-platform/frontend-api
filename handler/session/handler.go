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
	sessionID := c.Locals("session").(uint64)

	session := new(model.Session)

	err := database.Connection.Joins("ActiveSignin").
		Preload("ActiveSignin.User").
		Preload("ActiveSignin.User.UserEmailAddresses").
		Preload("ActiveSignin.User.UserPhoneNumbers").
		Preload("ActiveSignin.User.SocialConnections").
		Preload("Signins").
		Preload("Signins.User").
		Preload("Signins.User.UserEmailAddresses").
		Preload("Signins.User.UserPhoneNumbers").
		Preload("Signins.User.SocialConnections").
		Where("sessions.id = ?", sessionID).
		First(session).
		Error

	log.Println(session)
	if err != nil {
		log.Println(err)
		return handler.SendNotFound(c, nil, "Session not found")
	}

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

	handler.RemoveSessionFromCache(session.ID)

	database.Connection.Save(session)
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

		err = database.Connection.Transaction(
			func(tx *gorm.DB) error {
				tx.Delete(signIn)
				tx.Model(session).Update("active_sign_in_id", nil)
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

		handler.RemoveSessionFromCache(
			session.ID,
		)
		return handler.SendSuccess(
			c,
			session,
		)
	} else {
		err := database.Connection.Transaction(func(tx *gorm.DB) error {
			tx.Model(session).Update("active_sign_in_id", nil)
			tx.Where("session_id = ?", session.ID).Delete(&model.Signin{})
			return nil
		})
		if err != nil {
			return handler.SendInternalServerError(c, nil, "Failed to sign out")
		}

		handler.RemoveSessionFromCache(session.ID)
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
		session.ActiveSignin.User.ActiveOrganizationMembershipID = nil
		database.Connection.Save(session.ActiveSignin.User)
		session.ActiveSignin.ActiveOrganizationMembershipID = nil
		session.ActiveSignin.ActiveOrganizationMembershipID = nil
		database.Connection.Save(session.ActiveSignin)
		handler.RemoveSessionFromCache(session.ID)
		return handler.SendSuccess(c, session)
	}

	orgIDuint64, err := strconv.ParseUint(orgID, 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid org ID")
	}

	membership := new(model.OrganizationMembership)
	count := database.Connection.
		Model(&model.OrganizationMembership{}).
		Where("user_id = ? AND organization_id = ?", session.ActiveSignin.UserID, orgIDuint64).
		First(membership).
		RowsAffected
	if count == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "You are not a member of this organization")
	}

	session.ActiveSignin.User.ActiveOrganizationMembershipID = &membership.ID
	session.ActiveSignin.ActiveOrganizationMembershipID = &membership.ID
	database.Connection.Save(session.ActiveSignin.User)
	database.Connection.Save(session.ActiveSignin)
	handler.RemoveSessionFromCache(session.ID)

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
		session.ActiveSignin.User.ActiveWorkspaceMembershipID = nil
		session.ActiveSignin.User.ActiveOrganizationMembershipID = nil
		database.Connection.Save(session.ActiveSignin.User)
		session.ActiveSignin.ActiveWorkspaceMembershipID = nil
		session.ActiveSignin.ActiveOrganizationMembershipID = nil
		database.Connection.Save(session.ActiveSignin)
		handler.RemoveSessionFromCache(session.ID)
		return handler.SendSuccess(c, session)
	}

	workspaceIDuint64, err := strconv.ParseUint(workspaceID, 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid workspace ID")
	}

	membership := new(model.WorkspaceMembership)
	err = database.Connection.
		Model(&model.WorkspaceMembership{}).
		Where("user_id = ? AND workspace_id = ?", session.ActiveSignin.UserID, workspaceIDuint64).
		Joins("Organization").
		First(membership).
		Error
	if err != nil {
		log.Println(err)
		return fiber.NewError(fiber.StatusBadRequest, "You are not a member of this workspace")
	}

	session.ActiveSignin.User.ActiveWorkspaceMembershipID = &membership.ID
	session.ActiveSignin.User.ActiveOrganizationMembershipID = &membership.OrganizationMembershipID
	session.ActiveSignin.ActiveWorkspaceMembershipID = &membership.ID
	session.ActiveSignin.ActiveOrganizationMembershipID = &membership.OrganizationMembershipID
	database.Connection.Save(session.ActiveSignin.User)
	database.Connection.Save(session.ActiveSignin)
	handler.RemoveSessionFromCache(session.ID)

	return handler.SendSuccess(c, session)
}

func (h *Handler) GetToken(
	c *fiber.Ctx,
) error {
	deployment := handler.GetDeployment(c)
	deployment.LoadKepPair(database.Connection)
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

	sessionID := c.Locals("session").(uint64)
	session := new(model.Session)

	err := database.Connection.Joins("ActiveSignin").
		Joins("ActiveSignin.User").
		Joins("ActiveSignin.ActiveWorkspaceMembership").
		Joins("ActiveSignin.ActiveOrganizationMembership").
		Joins("ActiveSignin.User.PrimaryEmailAddress").
		Joins("ActiveSignin.User.PrimaryPhoneNumber").
		Joins("ActiveSignin.ActiveWorkspaceMembership.Workspace").
		Joins("ActiveSignin.ActiveOrganizationMembership.Organization").
		Preload("ActiveSignin.ActiveWorkspaceMembership.Roles").
		Preload("ActiveSignin.ActiveOrganizationMembership.Roles").
		Where("sessions.id = ?", sessionID).
		First(session).
		Error

	if err != nil {
		return handler.SendInternalServerError(c, nil, "Something went wrong")
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

	tok.Set("session_id", session.ID)
	if session.ActiveSignin.ActiveOrganizationMembership != nil {
		permissionsMap := map[string]bool{}
		for _, role := range session.ActiveSignin.ActiveOrganizationMembership.Roles {
			for _, rolepermissions := range role.Permissions {
				permissionsMap[rolepermissions] = true
			}
		}
		permissions := slices.Collect(maps.Keys(permissionsMap))
		tok.Set("organization_permissions", permissions)
		tok.Set("organization", *&session.ActiveSignin.ActiveOrganizationMembership.OrganizationID)
	}
	if session.ActiveSignin.ActiveWorkspaceMembership != nil {
		permissionsMap := map[string]bool{}
		for _, role := range session.ActiveSignin.ActiveWorkspaceMembership.Roles {
			for _, rolepermissions := range role.Permissions {
				permissionsMap[rolepermissions] = true
			}
		}
		permissions := slices.Collect(maps.Keys(permissionsMap))
		tok.Set("workspace_permissions", permissions)
		tok.Set("workspace", *&session.ActiveSignin.ActiveWorkspaceMembership.WorkspaceID)
	}

	signingAlg := template.CustomSigningKey.Algorithm
	secret := template.CustomSigningKey.Key
	if signingAlg == "" {
		signingAlg = "ES256"
	}

	if secret == "" {
		secret = deployment.KepPair.PrivateKey
	}

	claimsRaw := string(template.Template)
	if claimsRaw == "" {
		claimsRaw = "{}"
	}

	stralizedsignin, _ := json.Marshal(session.ActiveSignin)
	parsed := new(map[string]any)
	json.Unmarshal(stralizedsignin, parsed)

	claimsPopulated, err := raymond.Render(claimsRaw, parsed)

	if err != nil {
		return handler.SendInternalServerError(c, nil, "Failed to render claims")
	}

	claimsJson := new(map[string]any)
	err = json.Unmarshal([]byte(claimsPopulated), claimsJson)
	if err != nil {
		log.Println(err)
		return handler.SendInternalServerError(c, nil, "Failed to unmarshal claims")
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
