package oauth_consent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/config"
	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/handler"
)

type Handler struct {
	httpClientNoRedirect *http.Client
}

func NewHandler() *Handler {
	return &Handler{
		httpClientNoRedirect: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (h *Handler) Init(c fiber.Ctx) error {
	handoffID := strings.TrimSpace(c.Query("handoff_id"))
	if handoffID == "" {
		return handler.SendBadRequest(c, nil, "handoff_id is required")
	}

	deployment := handler.GetDeployment(c)
	handoff, err := loadOAuthConsentHandoff(c.RequestCtx(), handoffID)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid or expired consent handoff")
	}
	if uint64(handoff.DeploymentID) != deployment.ID {
		return handler.SendUnauthorized(c, nil, "Consent handoff is not valid for this deployment")
	}

	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Session required")
	}
	if err := setSessionConsentHandoff(c.RequestCtx(), session.ID, handoffID); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to initialize consent session")
	}

	consentURL := buildFrontendConsentURL(
		deployment.FrontendHost,
		deployment.IsProduction(),
		handoffID,
	)

	if !deployment.IsProduction() {
		devSession := strings.TrimSpace(c.GetRespHeader("X-Development-Session"))
		u, err := url.Parse(consentURL)
		if err == nil {
			q := u.Query()
			q.Set("__dev_session__", devSession)
			u.RawQuery = q.Encode()
			consentURL = u.String()
		}
	}

	return c.Redirect().Status(fiber.StatusTemporaryRedirect).To(consentURL)

}

func (h *Handler) Details(c fiber.Ctx) error {
	deployment := handler.GetDeployment(c)
	session := handler.GetSession(c)
	if session == nil || session.ActiveSigninID == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}
	if session.ActiveSignin == nil || session.ActiveSignin.UserID == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	handoffID, err := loadSessionConsentHandoff(c.RequestCtx(), session.ID)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Consent session is missing or expired")
	}

	handoff, err := loadOAuthConsentHandoff(c.RequestCtx(), handoffID)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid or expired consent handoff")
	}
	if uint64(handoff.DeploymentID) != deployment.ID {
		return handler.SendUnauthorized(c, nil, "Consent handoff is not valid for this deployment")
	}
	csrfToken, err := generateConsentCSRFToken()
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to initialize consent CSRF token")
	}
	if err := setSessionConsentCSRFToken(c.RequestCtx(), session.ID, handoffID, csrfToken); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to persist consent CSRF token")
	}

	resourceOptions, err := buildConsentResourceOptions(uint64(handoff.DeploymentID), *session.ActiveSignin.UserID, nil)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to load consent resource options")
	}

	// Skip-consent-when-covered: if the user has previously granted these
	// exact scopes to this client for an unambiguous resource, skip the UI
	// (unless the RP asked for `prompt=consent`). Mirrors what Google/Auth0
	// do — second-time RPs feel seamless to end users.
	defaultResource := pickAutoApproveResource(handoff.Resource, resourceOptions)
	autoApproveResource := ""
	grantCovers := false
	if defaultResource != "" {
		covers, err := userGrantCoversRequest(
			c.RequestCtx(),
			uint64(handoff.OAuthClientID),
			*session.ActiveSignin.UserID,
			handoff.Scopes,
			defaultResource,
		)
		if err != nil {
			return handler.SendInternalServerError(c, err, "Failed to check existing OAuth grant")
		}
		if covers {
			grantCovers = true
			autoApproveResource = defaultResource
		}
	}

	return handler.SendSuccess(c, fiber.Map{
		"client_name":           handoff.ClientName,
		"client_id":             handoff.ClientID,
		"redirect_uri":          handoff.RedirectURI,
		"scopes":                handoff.Scopes,
		"scope_definitions":     handoff.ScopeDefinitions,
		"resource":              handoff.Resource,
		"resource_options":      resourceOptions,
		"state":                 handoff.State,
		"expires_at":            handoff.ExpiresAt,
		"csrf_token":            csrfToken,
		"prompt":                handoff.Prompt,
		"max_age":               handoff.MaxAge,
		"grant_already_covers":  grantCovers,
		"auto_approve_resource": autoApproveResource,
	})
}

// pickAutoApproveResource returns the canonical resource URN to fast-path
// against, or "" when the consent flow must defer to the user. We can only
// auto-approve when there's exactly one resource we'd act on — either
// because the RP explicitly narrowed it via `resource`, or because the
// session has a single accessible option.
func pickAutoApproveResource(rpResource *string, options []consentResourceOption) string {
	if rpResource != nil {
		if trimmed := strings.TrimSpace(*rpResource); isCanonicalTenantResource(trimmed) {
			return trimmed
		}
	}
	if len(options) == 1 {
		return options[0].Value
	}
	return ""
}

// userGrantCoversRequest checks for an active oauth_client_grants row owned
// by `userID` that already covers every scope in `requestedScopes` for
// `resource`. Returns false (without error) when scopes is empty.
func userGrantCoversRequest(
	ctx context.Context,
	oauthClientID uint64,
	userID uint64,
	requestedScopes []string,
	resource string,
) (bool, error) {
	if len(requestedScopes) == 0 {
		return false, nil
	}
	scopesJSON, err := json.Marshal(requestedScopes)
	if err != nil {
		return false, err
	}
	var exists bool
	if err := database.Connection.WithContext(ctx).Raw(`
		SELECT EXISTS (
			SELECT 1 FROM oauth_client_grants
			WHERE oauth_client_id = ?
			  AND granted_by_user_id = ?
			  AND status = 'active'
			  AND (expires_at IS NULL OR expires_at > NOW())
			  AND resource = ?
			  AND scopes @> ?::jsonb
		)
	`, oauthClientID, userID, resource, string(scopesJSON)).Scan(&exists).Error; err != nil {
		return false, err
	}
	return exists, nil
}

func (h *Handler) Submit(c fiber.Ctx) error {
	request, validation := handler.Validate[submitConsentRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	deployment := handler.GetDeployment(c)
	session := handler.GetSession(c)
	if session == nil || session.ActiveSigninID == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}
	if session.ActiveSignin == nil || session.ActiveSignin.UserID == nil {
		return handler.SendUnauthorized(c, nil, "No active sign in")
	}

	handoffID, err := loadSessionConsentHandoff(c.RequestCtx(), session.ID)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Consent session is missing or expired")
	}

	handoff, err := loadOAuthConsentHandoff(c.RequestCtx(), handoffID)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid or expired consent handoff")
	}
	if uint64(handoff.DeploymentID) != deployment.ID {
		return handler.SendUnauthorized(c, nil, "Consent handoff is not valid for this deployment")
	}
	expectedCSRFToken, err := loadSessionConsentCSRFToken(c.RequestCtx(), session.ID, handoffID)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Consent CSRF token is missing or expired")
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(request.CSRFToken)), []byte(strings.TrimSpace(expectedCSRFToken))) != 1 {
		return handler.SendUnauthorized(c, nil, "Invalid consent CSRF token")
	}

	action := strings.ToLower(strings.TrimSpace(request.Action))
	var normalizedAction string
	switch action {
	case "approve":
		normalizedAction = "approve"
	case "deny":
		normalizedAction = "deny"
	default:
		return handler.SendBadRequest(c, nil, "action must be approve or deny")
	}

	payload := url.Values{}
	payload.Set("request_token", strings.TrimSpace(handoff.RequestToken))
	payload.Set("action", normalizedAction)
	payload.Set("user_id", strconv.FormatUint(*session.ActiveSignin.UserID, 10))
	// OIDC: forward the live Wacht session id so platform-api can bind the
	// issued auth code / tokens to the exact session that approved consent
	// instead of guessing via "most recent session for user".
	payload.Set("session_id", strconv.FormatUint(session.ID, 10))
	if normalizedAction == "approve" {
		grantedResource := strings.TrimSpace(request.GrantedResource)
		if grantedResource == "" {
			return handler.SendBadRequest(c, nil, "granted_resource is required")
		}
		if !isCanonicalTenantResource(grantedResource) {
			return handler.SendBadRequest(c, nil, "granted_resource must be a canonical Wacht URN (e.g. urn:wacht:workspace:123)")
		}
		allowedOptions, err := buildConsentResourceOptions(uint64(handoff.DeploymentID), *session.ActiveSignin.UserID, []string{grantedResource})
		if err != nil {
			return handler.SendInternalServerError(c, err, "Failed to validate consent resource")
		}
		if len(allowedOptions) == 0 {
			return handler.SendForbidden(c, nil, "You do not have access to this resource")
		}

		effectiveScopes, err := resolveEffectiveScopes(
			c.RequestCtx(),
			uint64(handoff.DeploymentID),
			*session.ActiveSignin.UserID,
			grantedResource,
			handoff.Scopes,
			handoff.ScopeDefinitions,
		)
		if err != nil {
			return handler.SendInternalServerError(c, err, "Failed to resolve effective scopes")
		}

		payload.Set("granted_resource", grantedResource)
		payload.Set("scope", strings.Join(effectiveScopes, " "))
	}
	req, err := http.NewRequestWithContext(
		c.RequestCtx(),
		http.MethodPost,
		handoff.Issuer+"/oauth/consent/submit",
		strings.NewReader(payload.Encode()),
	)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to build OAuth consent request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret := oauthConsentSubmitSecret(); secret != "" {
		req.Header.Set("X-OAuth-Consent-Secret", secret)
	}

	resp, err := h.httpClientNoRedirect.Do(req)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Failed to submit OAuth consent action")
	}
	defer resp.Body.Close()

	location := strings.TrimSpace(resp.Header.Get("Location"))
	if (resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect) && location != "" {
		_ = deleteOAuthConsentHandoff(c.RequestCtx(), handoffID)
		_ = deleteSessionConsentHandoff(c.RequestCtx(), session.ID)
		_ = deleteSessionConsentCSRFToken(c.RequestCtx(), session.ID, handoffID)
		return c.Redirect().Status(fiber.StatusFound).To(location)
	}

	// Cap error-body relay so a misbehaving platform-api can't flood us.
	const maxErrorBodyBytes = 64 * 1024
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_ = deleteOAuthConsentHandoff(c.RequestCtx(), handoffID)
		_ = deleteSessionConsentHandoff(c.RequestCtx(), session.ID)
		_ = deleteSessionConsentCSRFToken(c.RequestCtx(), session.ID, handoffID)
		return handler.SendSuccess(c, fiber.Map{"ok": true})
	}

	return c.Status(resp.StatusCode).Send(body)
}

func buildFrontendConsentURL(frontendHost string, isProduction bool, handoffID string) string {
	consentURL := fmt.Sprintf("%s/oauth/consent", hostBaseURL(frontendHost, isProduction))
	u, err := url.Parse(consentURL)
	if err != nil {
		return consentURL
	}
	q := u.Query()
	q.Set("handoff_id", strings.TrimSpace(handoffID))
	u.RawQuery = q.Encode()
	return u.String()
}

func hostBaseURL(host string, isProduction bool) string {
	host = strings.TrimSpace(host)
	scheme := "https"
	if !isProduction && (strings.Contains(host, "localhost") || strings.HasPrefix(host, "127.0.0.1")) {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

func oauthConsentSubmitSecret() string {
	key := strings.TrimSpace(config.GetEnv("ENCRYPTION_KEY", ""))
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("oauth-consent-submit-v1:" + key))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func validateIssuer(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", errors.New("issuer must be a valid URL")
	}

	if u.Scheme != "https" && u.Scheme != "http" {
		return "", errors.New("issuer must use http or https")
	}

	return strings.TrimSuffix(u.String(), "/"), nil
}

func oauthConsentHandoffRedisKey(handoffID string) string {
	return fmt.Sprintf("oauth:consent:handoff:%s", handoffID)
}

func loadOAuthConsentHandoff(ctx context.Context, handoffID string) (*oauthConsentHandoffPayload, error) {
	payloadJSON, err := database.Redis.Get(ctx, oauthConsentHandoffRedisKey(handoffID)).Result()
	if err != nil {
		return nil, err
	}

	var payload oauthConsentHandoffPayload
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		return nil, err
	}

	payload.Issuer, err = validateIssuer(payload.Issuer)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(payload.RequestToken) == "" {
		return nil, errors.New("missing request token")
	}

	return &payload, nil
}

func deleteOAuthConsentHandoff(ctx context.Context, handoffID string) error {
	return database.Redis.Del(ctx, oauthConsentHandoffRedisKey(handoffID)).Err()
}

func sessionConsentHandoffRedisKey(sessionID uint64) string {
	return fmt.Sprintf("oauth:consent:session:%d", sessionID)
}

func setSessionConsentHandoff(ctx context.Context, sessionID uint64, handoffID string) error {
	return database.Redis.Set(ctx, sessionConsentHandoffRedisKey(sessionID), handoffID, 15*time.Minute).Err()
}

func loadSessionConsentHandoff(ctx context.Context, sessionID uint64) (string, error) {
	return database.Redis.Get(ctx, sessionConsentHandoffRedisKey(sessionID)).Result()
}

func deleteSessionConsentHandoff(ctx context.Context, sessionID uint64) error {
	return database.Redis.Del(ctx, sessionConsentHandoffRedisKey(sessionID)).Err()
}

func sessionConsentCSRFRedisKey(sessionID uint64, handoffID string) string {
	return fmt.Sprintf("oauth:consent:csrf:%d:%s", sessionID, handoffID)
}

func setSessionConsentCSRFToken(ctx context.Context, sessionID uint64, handoffID string, token string) error {
	return database.Redis.Set(ctx, sessionConsentCSRFRedisKey(sessionID, handoffID), token, 15*time.Minute).Err()
}

func loadSessionConsentCSRFToken(ctx context.Context, sessionID uint64, handoffID string) (string, error) {
	return database.Redis.Get(ctx, sessionConsentCSRFRedisKey(sessionID, handoffID)).Result()
}

func deleteSessionConsentCSRFToken(ctx context.Context, sessionID uint64, handoffID string) error {
	return database.Redis.Del(ctx, sessionConsentCSRFRedisKey(sessionID, handoffID)).Err()
}

func generateConsentCSRFToken() (string, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes[:]), nil
}

func isCanonicalTenantResource(resource string) bool {
	if after, ok := strings.CutPrefix(resource, "urn:wacht:organization:"); ok {
		id, err := strconv.ParseUint(after, 10, 64)
		return err == nil && id > 0
	}
	if after, ok := strings.CutPrefix(resource, "urn:wacht:workspace:"); ok {
		id, err := strconv.ParseUint(after, 10, 64)
		return err == nil && id > 0
	}
	if after, ok := strings.CutPrefix(resource, "urn:wacht:user:"); ok {
		id, err := strconv.ParseUint(after, 10, 64)
		return err == nil && id > 0
	}
	return false
}

func buildConsentResourceOptions(
	deploymentID uint64,
	userID uint64,
	allowed []string,
) ([]consentResourceOption, error) {
	allowedSet := map[string]struct{}{}
	for _, item := range allowed {
		item = strings.TrimSpace(item)
		if item != "" {
			allowedSet[item] = struct{}{}
		}
	}
	filterAllowed := len(allowedSet) > 0
	options := make([]consentResourceOption, 0)

	userResource := fmt.Sprintf("urn:wacht:user:%d", userID)
	if !filterAllowed {
		options = append(options, consentResourceOption{
			Value: userResource,
			Type:  "user",
			ID:    fmt.Sprintf("%d", userID),
			Label: "Personal Profile",
		})
	} else {
		if _, ok := allowedSet[userResource]; ok {
			options = append(options, consentResourceOption{
				Value: userResource,
				Type:  "user",
				ID:    fmt.Sprintf("%d", userID),
				Label: "Personal Profile",
			})
		}
	}

	type orgRow struct {
		ID   uint64
		Name string
	}
	var orgs []orgRow
	if err := database.Connection.Raw(`
		SELECT o.id, o.name
		FROM organization_memberships om
		INNER JOIN organizations o
		    ON o.id = om.organization_id
		   AND o.deployment_id = ?
		WHERE om.user_id = ?
		  AND om.deleted_at IS NULL
		ORDER BY o.name ASC
	`, deploymentID, userID).Scan(&orgs).Error; err != nil {
		return nil, err
	}
	for _, org := range orgs {
		value := fmt.Sprintf("urn:wacht:organization:%d", org.ID)
		if filterAllowed {
			if _, ok := allowedSet[value]; !ok {
				continue
			}
		}
		options = append(options, consentResourceOption{
			Value: value,
			Type:  "organization",
			ID:    fmt.Sprintf("%d", org.ID),
			Label: fmt.Sprintf("%s (Organization)", org.Name),
		})
	}

	type workspaceRow struct {
		ID               uint64
		Name             string
		OrganizationName string
	}
	var workspaces []workspaceRow
	if err := database.Connection.Raw(`
		SELECT w.id, w.name, o.name AS organization_name
		FROM workspace_memberships wm
		INNER JOIN workspaces w
		    ON w.id = wm.workspace_id
		   AND w.deployment_id = ?
		INNER JOIN organizations o
		    ON o.id = wm.organization_id
		WHERE wm.user_id = ?
		  AND wm.deleted_at IS NULL
		ORDER BY o.name ASC, w.name ASC
	`, deploymentID, userID).Scan(&workspaces).Error; err != nil {
		return nil, err
	}
	for _, workspace := range workspaces {
		value := fmt.Sprintf("urn:wacht:workspace:%d", workspace.ID)
		if filterAllowed {
			if _, ok := allowedSet[value]; !ok {
				continue
			}
		}
		options = append(options, consentResourceOption{
			Value: value,
			Type:  "workspace",
			ID:    fmt.Sprintf("%d", workspace.ID),
			Label: fmt.Sprintf("%s / %s", workspace.OrganizationName, workspace.Name),
		})
	}

	return options, nil
}

func resolveEffectiveScopes(
	ctx context.Context,
	deploymentID uint64,
	userID uint64,
	resource string,
	requestedScopes []string,
	definitions []oauthConsentScopeDefinition,
) ([]string, error) {
	resourceType := detectResourceType(resource)
	if resourceType == "" {
		return nil, errors.New("unsupported resource type")
	}

	permissionSet, err := loadPermissionSetForResource(ctx, deploymentID, userID, resource)
	if err != nil {
		return nil, err
	}

	byScope := map[string]oauthConsentScopeDefinition{}
	for _, def := range definitions {
		scope := strings.TrimSpace(def.Scope)
		if scope == "" {
			continue
		}
		byScope[scope] = def
	}

	out := make([]string, 0, len(requestedScopes))
	for _, scope := range requestedScopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		def, ok := byScope[scope]
		if !ok {
			continue
		}
		if def.Archived {
			continue
		}
		if !scopeAllowsResourceType(def, resourceType) {
			continue
		}
		if !scopePermissionSatisfied(def, resourceType, permissionSet) {
			continue
		}
		out = append(out, scope)
	}
	return out, nil
}

func scopeAllowsResourceType(def oauthConsentScopeDefinition, resourceType string) bool {
	category := strings.ToLower(strings.TrimSpace(def.Category))
	if category == "" {
		return true
	}
	return category == resourceType
}

func scopePermissionSatisfied(
	def oauthConsentScopeDefinition,
	resourceType string,
	permissionSet map[string]struct{},
) bool {
	var required string
	switch resourceType {
	case "organization":
		if def.OrganizationPermission != nil {
			required = strings.TrimSpace(*def.OrganizationPermission)
		}
	case "workspace":
		if def.WorkspacePermission != nil {
			required = strings.TrimSpace(*def.WorkspacePermission)
		}
	}
	if required == "" {
		return true
	}
	if _, ok := permissionSet[required]; !ok {
		return false
	}
	return true
}

func loadPermissionSetForResource(
	ctx context.Context,
	deploymentID uint64,
	userID uint64,
	resource string,
) (map[string]struct{}, error) {
	resourceType := detectResourceType(resource)
	out := map[string]struct{}{}
	if resourceType == "personal" {
		return out, nil
	}

	if resourceType == "organization" {
		orgID, ok := parseResourceID(resource, "urn:wacht:organization:")
		if !ok {
			return nil, errors.New("invalid organization resource")
		}
		var permissions []string
		if err := database.Connection.WithContext(ctx).Raw(`
			SELECT DISTINCT perm.permission
			FROM organization_memberships om
			INNER JOIN organizations o
			  ON o.id = om.organization_id
			 AND o.deployment_id = ?
			 AND o.deleted_at IS NULL
			INNER JOIN organization_membership_roles omr
			  ON omr.organization_membership_id = om.id
			INNER JOIN organization_roles r
			  ON r.id = omr.organization_role_id
			CROSS JOIN LATERAL unnest(COALESCE(r.permissions, ARRAY[]::text[])) AS perm(permission)
			WHERE om.organization_id = ?
			  AND om.user_id = ?
			  AND om.deleted_at IS NULL
		`, deploymentID, orgID, userID).Scan(&permissions).Error; err != nil {
			return nil, err
		}
		for _, p := range permissions {
			if p != "" {
				out[p] = struct{}{}
			}
		}
		return out, nil
	}

	if resourceType == "workspace" {
		workspaceID, ok := parseResourceID(resource, "urn:wacht:workspace:")
		if !ok {
			return nil, errors.New("invalid workspace resource")
		}
		var permissions []string
		if err := database.Connection.WithContext(ctx).Raw(`
			SELECT DISTINCT perm.permission
			FROM workspace_memberships wm
			INNER JOIN workspaces w
			  ON w.id = wm.workspace_id
			 AND w.deployment_id = ?
			 AND w.deleted_at IS NULL
			INNER JOIN workspace_membership_roles wmr
			  ON wmr.workspace_membership_id = wm.id
			INNER JOIN workspace_roles r
			  ON r.id = wmr.workspace_role_id
			CROSS JOIN LATERAL unnest(COALESCE(r.permissions, ARRAY[]::text[])) AS perm(permission)
			WHERE wm.workspace_id = ?
			  AND wm.user_id = ?
			  AND wm.deleted_at IS NULL
		`, deploymentID, workspaceID, userID).Scan(&permissions).Error; err != nil {
			return nil, err
		}
		for _, p := range permissions {
			if p != "" {
				out[p] = struct{}{}
			}
		}
		return out, nil
	}

	return nil, errors.New("unsupported resource type")
}

func detectResourceType(resource string) string {
	switch {
	case strings.HasPrefix(resource, "urn:wacht:user:"):
		return "personal"
	case strings.HasPrefix(resource, "urn:wacht:organization:"):
		return "organization"
	case strings.HasPrefix(resource, "urn:wacht:workspace:"):
		return "workspace"
	default:
		return ""
	}
}

func parseResourceID(resource string, prefix string) (uint64, bool) {
	if !strings.HasPrefix(resource, prefix) {
		return 0, false
	}
	id, err := strconv.ParseUint(strings.TrimPrefix(resource, prefix), 10, 64)
	if err != nil || id == 0 {
		return 0, false
	}
	return id, true
}
