package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/pkg/idgen"
	"github.com/lib/pq"

	"gorm.io/gorm"
)

type Service struct {
	db *gorm.DB
}

type McpConnectResult struct {
	RequiresOAuth bool
	OAuthURL      string
}

type mcpOAuthState struct {
	DeploymentID uint64 `json:"deployment_id,string"`
	SessionID    uint64 `json:"session_id,string"`
	AgentID      uint64 `json:"agent_id,string"`
	McpServerID  uint64 `json:"mcp_server_id,string"`
	ContextGroup string `json:"context_group"`

	CodeVerifier string `json:"code_verifier"`
	ClientID     string `json:"client_id"`
	TokenURL     string `json:"token_url"`
	RedirectURI  string `json:"redirect_uri"`
	Resource     string `json:"resource,omitempty"`
	RedirectBack string `json:"redirect_back,omitempty"`
}

type mcpOAuthDiscovery struct {
	authorizationEndpoint string
	tokenEndpoint         string
	registrationEndpoint  string
	resource              string
	scopes                []string
}

func NewService() *Service {
	return &Service{
		db: database.Connection,
	}
}

// GetActiveAgentSession retrieves an active agent session for the given session and deployment
func (s *Service) GetActiveAgentSession(sessionID, deploymentID uint64) (*model.AgentSession, error) {
	var agentSession model.AgentSession
	err := s.db.Where(
		"session_id = ? AND deployment_id = ? AND (expires_at IS NULL OR expires_at > ?)",
		sessionID, deploymentID, time.Now(),
	).First(&agentSession).Error
	if err != nil {
		return nil, err
	}
	return &agentSession, nil
}

func (s *Service) CreateContext(
	deploymentID uint64,
	contextGroup *string,
	title string,
	systemInstructions *string,
) (*model.AgentExecutionContext, error) {
	context := &model.AgentExecutionContext{
		Model: model.Model{
			ID: idgen.NextID(),
		},
		DeploymentID:       deploymentID,
		Title:              title,
		SystemInstructions: systemInstructions,
		ContextGroup:       contextGroup,
		Status:             model.ExecutionStatusIdle,
		LastActivityAt:     time.Now(),
	}

	if err := s.db.Create(context).Error; err != nil {
		return nil, fmt.Errorf("failed to create context: %w", err)
	}

	return context, nil
}

func (s *Service) ListContexts(
	deploymentID uint64,
	contextGroup *string,
	params ListContextsRequest,
) (*ListContextsResponse, error) {
	query := s.db.Model(&model.AgentExecutionContext{}).
		Where("deployment_id = ?", deploymentID)

	if contextGroup != nil && *contextGroup != "" {
		query = query.Where("context_group = ?", *contextGroup)
	}

	if params.Status != "" {
		query = query.Where("status = ?", params.Status)
	}

	if params.Search != "" {
		searchPattern := "%" + params.Search + "%"
		query = query.Where("title ILIKE ?", searchPattern)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("failed to count contexts: %w", err)
	}

	limit := params.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := params.Offset

	var contexts []model.AgentExecutionContext
	if err := query.
		Order("last_activity_at DESC").
		Limit(limit + 1).
		Offset(offset).
		Find(&contexts).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch contexts: %w", err)
	}

	hasMore := len(contexts) > limit
	if hasMore {
		contexts = contexts[:limit]
	}

	data := make([]interface{}, len(contexts))
	for i, ctx := range contexts {
		data[i] = ctx
	}

	return &ListContextsResponse{
		Data:    data,
		HasMore: hasMore,
		Limit:   &limit,
		Offset:  &offset,
	}, nil
}

func (s *Service) GetContext(
	deploymentID uint64,
	contextGroup *string,
	contextID uint64,
) (*model.AgentExecutionContext, error) {
	query := s.db.Where("id = ? AND deployment_id = ?", contextID, deploymentID)

	if contextGroup != nil && *contextGroup != "" {
		query = query.Where("context_group = ?", *contextGroup)
	}

	var context model.AgentExecutionContext
	if err := query.First(&context).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("context not found or access denied")
		}
		return nil, fmt.Errorf("failed to fetch context: %w", err)
	}

	return &context, nil
}

func (s *Service) DeleteContext(deploymentID uint64, contextGroup *string, contextID uint64) error {
	query := s.db.Where("id = ? AND deployment_id = ?", contextID, deploymentID)

	if contextGroup != nil && *contextGroup != "" {
		query = query.Where("context_group = ?", *contextGroup)
	}

	result := query.Delete(&model.AgentExecutionContext{})

	if result.Error != nil {
		return fmt.Errorf("failed to delete context: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("context not found or access denied")
	}

	return nil
}

func (s *Service) UpdateContext(
	deploymentID uint64,
	contextGroup *string,
	contextID uint64,
	title string,
) error {
	query := s.db.Model(&model.AgentExecutionContext{}).
		Where("id = ? AND deployment_id = ?", contextID, deploymentID)

	if contextGroup != nil && *contextGroup != "" {
		query = query.Where("context_group = ?", *contextGroup)
	}

	result := query.Update("title", title)
	if result.Error != nil {
		return fmt.Errorf("failed to update context: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("context not found or access denied")
	}

	return nil
}

func (s *Service) GetContextMessages(
	deploymentID uint64,
	contextGroup *string,
	contextID uint64,
	limit int,
	beforeID, afterID string,
) ([]ConversationMessage, bool, error) {
	var context model.AgentExecutionContext
	query := s.db.Where("deployment_id = ? AND id = ?", deploymentID, contextID)
	if contextGroup != nil {
		query = query.Where("context_group = ?", *contextGroup)
	}

	if err := query.First(&context).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, false, fmt.Errorf("context not found or access denied")
		}
		return nil, false, fmt.Errorf("failed to fetch context: %w", err)
	}

	// Filter to only include displayable message types
	allowedTypes := []string{
		"user_message",
		"agent_response",
		"assistant_acknowledgment",
		"system_decision",
		"user_input_request",
	}

	messagesQuery := s.db.Model(&model.Conversation{}).
		Select("id, context_id, message_type, content - 'thought_signature' as content, timestamp, metadata").
		Where("context_id = ?", contextID).
		Where("content->>'type' IN ?", allowedTypes)

	if beforeID != "" {
		messagesQuery = messagesQuery.Where("id < ?", beforeID)
	}
	if afterID != "" {
		messagesQuery = messagesQuery.Where("id > ?", afterID).Order("id ASC")
	} else {
		messagesQuery = messagesQuery.Order("id DESC")
	}

	messagesQuery = messagesQuery.Limit(limit + 1)

	var conversations []model.Conversation
	if err := messagesQuery.Find(&conversations).Error; err != nil {
		return nil, false, fmt.Errorf("failed to fetch messages: %w", err)
	}

	hasMore := len(conversations) > limit
	if hasMore {
		conversations = conversations[:limit]
	}

	if afterID != "" {
		for i := len(conversations)/2 - 1; i >= 0; i-- {
			opp := len(conversations) - 1 - i
			conversations[i], conversations[opp] = conversations[opp], conversations[i]
		}
	}

	messages := make([]ConversationMessage, len(conversations))
	for i, conv := range conversations {
		role := "system"
		switch conv.MessageType {
		case "user_message":
			role = "user"
		case "agent_response", "assistant_acknowledgment", "action_execution_result":
			role = "assistant"
		case "user_input_request", "system_decision", "context_results", "execution_summary":
			role = "system"
		}

		messages[i] = ConversationMessage{
			ID:        fmt.Sprintf("%d", conv.ID),
			Role:      role,
			Content:   conv.Content,
			Timestamp: conv.Timestamp,
			Metadata:  extractMetadata(conv.MessageType),
		}
	}

	return messages, hasMore, nil
}

func extractMetadata(messageType string) json.RawMessage {
	metadata := map[string]string{
		"message_type": messageType,
	}
	data, _ := json.Marshal(metadata)
	return data
}

func (s *Service) GetActiveIntegrations(deploymentID uint64, agentName string, contextGroup string) ([]model.AgentIntegration, error) {
	var agent model.AiAgent
	if err := s.db.Where("deployment_id = ? AND name = ?", deploymentID, agentName).First(&agent).Error; err != nil {
		return nil, fmt.Errorf("agent not found: %w", err)
	}

	var integrations []model.AgentIntegration

	err := s.db.
		Table("agent_integrations ai").
		Select("ai.*").
		Joins("JOIN active_agent_integrations aai ON ai.id = aai.integration_id").
		Where("aai.deployment_id = ? AND aai.agent_id = ? AND aai.context_group = ?", deploymentID, agent.ID, contextGroup).
		Find(&integrations).Error

	if err != nil {
		return nil, fmt.Errorf("failed to fetch active integrations: %w", err)
	}

	return integrations, nil
}

func (s *Service) RemoveIntegration(deploymentID uint64, contextGroup string, integrationID uint64) error {
	result := s.db.Where("deployment_id = ? AND context_group = ? AND integration_id = ?",
		deploymentID, contextGroup, integrationID).Delete(&model.ActiveAgentIntegration{})

	if result.Error != nil {
		return fmt.Errorf("failed to remove integration: %w", result.Error)
	}

	return nil
}

func (s *Service) ListAvailableIntegrations(deploymentID uint64, agentName string, contextGroup *string) ([]map[string]interface{}, error) {
	if contextGroup == nil || *contextGroup == "" {
		return nil, fmt.Errorf("context group (agent name) is required")
	}

	var agent model.AiAgent
	if err := s.db.Where("deployment_id = ? AND name = ?", deploymentID, agentName).First(&agent).Error; err != nil {
		return nil, fmt.Errorf("agent not found: %w", err)
	}

	var integrations []model.AgentIntegration
	if err := s.db.Where("deployment_id = ? AND agent_id = ?", deploymentID, agent.ID).Find(&integrations).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch integrations: %w", err)
	}

	var activeIntegrations []model.ActiveAgentIntegration
	if err := s.db.Where("deployment_id = ? AND agent_id = ? AND context_group = ?", deploymentID, agent.ID, *contextGroup).
		Find(&activeIntegrations).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch active integrations: %w", err)
	}

	activeMap := make(map[uint64]model.ActiveAgentIntegration)
	for _, active := range activeIntegrations {
		activeMap[active.IntegrationID] = active
	}

	result := make([]map[string]any, len(integrations))
	for i, integration := range integrations {
		active, isActive := activeMap[integration.ID]

		res := map[string]any{
			"id":               fmt.Sprintf("%d", integration.ID),
			"name":             integration.Name,
			"integration_type": integration.IntegrationType,
			"agent_id":         fmt.Sprintf("%d", integration.AgentID),
			"is_active":        isActive,
		}

		if isActive {
			res["connection_metadata"] = active.ConnectionMetadata
		}

		result[i] = res
	}

	return result, nil
}

func (s *Service) GenerateConsentURL(deploymentID uint64, contextGroup string, integrationID uint64, redirectURL string) (string, string, error) {
	var integration model.AgentIntegration
	if err := s.db.Where("id = ? AND deployment_id = ?", integrationID, deploymentID).First(&integration).Error; err != nil {
		return "", "", fmt.Errorf("integration not found")
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(integration.Config), &config); err != nil {
		return "", "", fmt.Errorf("invalid integration config")
	}

	state := uuid.New().String()

	consentState := ConsentState{
		DeploymentID:  fmt.Sprintf("%d", deploymentID),
		IntegrationID: fmt.Sprintf("%d", integrationID),
		AgentID:       fmt.Sprintf("%d", integration.AgentID),
		ContextGroup:  contextGroup,
		RedirectURL:   redirectURL,
		CreatedAt:     time.Now().Unix(),
	}

	stateJSON, err := json.Marshal(consentState)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal state: %w", err)
	}

	redisKey := fmt.Sprintf("teams:consent:%s", state)
	if err := database.Redis.Set(context.Background(), redisKey, stateJSON, 15*time.Minute).Err(); err != nil {
		return "", "", fmt.Errorf("failed to store state: %w", err)
	}

	switch integration.IntegrationType {
	case "teams":
		appID, _ := config["app_id"].(string)
		if appID == "" {
			return "", "", fmt.Errorf("Teams App ID not configured")
		}

		return fmt.Sprintf(
			"https://login.microsoftonline.com/common/adminconsent?client_id=%s&redirect_uri=%s&state=%s",
			appID,
			"https://agentlink.wacht.services/service/teams/consent/callback",
			state,
		), state, nil

	case "clickup":
		clientID, _ := config["app_id"].(string)

		return fmt.Sprintf(
			"https://app.clickup.com/api?client_id=%s&redirect_uri=%s&state=%s",
			clientID,
			"https://agentlink.wacht.services/service/clickup/consent/callback",
			state,
		), state, nil

	default:
		return "", "", fmt.Errorf("integration type '%s' does not support OAuth consent flow", integration.IntegrationType)
	}
}

func (s *Service) GetAllowlistedAgents(deploymentID uint64, agentIDs []int64) ([]AgentWithIntegrations, error) {
	type allowlistedAgentRow struct {
		ID               uint64          `gorm:"column:id"`
		Name             string          `gorm:"column:name"`
		Description      string          `gorm:"column:description"`
		IntegrationsJSON json.RawMessage `gorm:"column:integrations_json"`
		McpServersJSON   json.RawMessage `gorm:"column:mcp_servers_json"`
	}

	var rows []allowlistedAgentRow
	if err := s.db.Raw(`
		WITH selected_agents AS (
			SELECT a.id, a.name, a.description
			FROM ai_agents a
			WHERE a.deployment_id = ? AND a.id = ANY(?)
		)
		SELECT
			a.id,
			a.name,
			a.description,
			COALESCE((
				SELECT json_agg(
					json_build_object(
						'id', ai.id,
						'created_at', ai.created_at,
						'updated_at', ai.updated_at,
						'deployment_id', ai.deployment_id,
						'agent_id', ai.agent_id,
						'integration_type', ai.integration_type,
						'name', ai.name,
						'config', ai.config
					)
					ORDER BY ai.created_at DESC
				)
				FROM agent_integrations ai
				WHERE ai.deployment_id = ? AND ai.agent_id = a.id
			), '[]'::json) AS integrations_json,
			COALESCE((
				SELECT json_agg(
					json_build_object(
						'id', m.id::text,
						'name', m.name,
						'requires_connection', (
							COALESCE(m.config->'auth'->>'type', '') IN (
								'oauth_authorization_code_public_pkce',
								'oauth_authorization_code_confidential_pkce'
							)
						)
					)
					ORDER BY m.name ASC
				)
				FROM ai_agent_mcp_servers ams
				JOIN mcp_servers m
					ON m.id = ams.mcp_server_id
					AND m.deployment_id = ams.deployment_id
				WHERE ams.deployment_id = ? AND ams.agent_id = a.id
			), '[]'::json) AS mcp_servers_json
		FROM selected_agents a
		ORDER BY a.name ASC
	`, deploymentID, pq.Int64Array(agentIDs), deploymentID, deploymentID).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch agents: %w", err)
	}

	result := make([]AgentWithIntegrations, 0, len(rows))
	for _, row := range rows {
		var integrations []model.AgentIntegration
		if len(row.IntegrationsJSON) > 0 {
			if err := json.Unmarshal(row.IntegrationsJSON, &integrations); err != nil {
				return nil, fmt.Errorf("failed to parse integrations for agent %d: %w", row.ID, err)
			}
		}

		var mcpServers []AgentMcpServer
		if len(row.McpServersJSON) > 0 {
			if err := json.Unmarshal(row.McpServersJSON, &mcpServers); err != nil {
				return nil, fmt.Errorf("failed to parse MCP servers for agent %d: %w", row.ID, err)
			}
		}

		result = append(result, AgentWithIntegrations{
			ID:           fmt.Sprintf("%d", row.ID),
			Name:         row.Name,
			Description:  row.Description,
			Integrations: integrations,
			McpServers:   mcpServers,
		})
	}

	return result, nil
}

func randomURLSafe(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func randomPKCEVerifier() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	// RFC 7636 URL-safe base64 without padding.
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func parseBearerResourceMetadata(authHeader string) string {
	for _, part := range strings.Split(authHeader, ",") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(strings.ToLower(part), "resource_metadata=") {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		return strings.Trim(kv[1], "\"")
	}
	return ""
}

func parseTokenExpiry(expiresIn any) *time.Time {
	var seconds int64
	switch value := expiresIn.(type) {
	case float64:
		seconds = int64(value)
	case int64:
		seconds = value
	case int:
		seconds = int64(value)
	}
	if seconds <= 0 {
		return nil
	}
	expiresAt := time.Now().UTC().Add(time.Duration(seconds) * time.Second)
	return &expiresAt
}

func (s *Service) discoverMcpOAuth(endpoint string) (*mcpOAuthDiscovery, error) {
	httpClient := &http.Client{Timeout: 12 * time.Second}
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build discovery request: %w", err)
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to probe MCP endpoint: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusUnauthorized && response.StatusCode != http.StatusForbidden {
		return nil, nil
	}

	wwwAuth := response.Header.Get("Www-Authenticate")
	resourceMetadataURL := parseBearerResourceMetadata(wwwAuth)
	if resourceMetadataURL == "" {
		return nil, fmt.Errorf("missing resource_metadata in WWW-Authenticate")
	}

	resourceResponse, err := httpClient.Get(resourceMetadataURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch protected resource metadata: %w", err)
	}
	defer resourceResponse.Body.Close()

	resourceBody, err := io.ReadAll(resourceResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read protected resource metadata: %w", err)
	}

	var resourceMetadata map[string]any
	if err := json.Unmarshal(resourceBody, &resourceMetadata); err != nil {
		return nil, fmt.Errorf("failed to parse protected resource metadata: %w", err)
	}

	var authServer string
	if authorizationServers, ok := resourceMetadata["authorization_servers"].([]any); ok && len(authorizationServers) > 0 {
		if server, ok := authorizationServers[0].(string); ok {
			authServer = strings.TrimRight(server, "/")
		}
	}
	if authServer == "" {
		if parsedResource, err := url.Parse(resourceMetadataURL); err == nil {
			authServer = parsedResource.Scheme + "://" + parsedResource.Host
		}
	}
	if authServer == "" {
		return nil, fmt.Errorf("failed to resolve authorization server")
	}

	authMetadataURL := authServer + "/.well-known/oauth-authorization-server"
	authResponse, err := httpClient.Get(authMetadataURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch authorization metadata: %w", err)
	}
	if authResponse.StatusCode >= 400 {
		authResponse.Body.Close()
		return nil, fmt.Errorf("authorization metadata request failed: %d", authResponse.StatusCode)
	}
	defer authResponse.Body.Close()

	authBody, err := io.ReadAll(authResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read authorization metadata: %w", err)
	}

	var authMetadata map[string]any
	if err := json.Unmarshal(authBody, &authMetadata); err != nil {
		return nil, fmt.Errorf("failed to parse authorization metadata: %w", err)
	}

	authorizationEndpoint, _ := authMetadata["authorization_endpoint"].(string)
	tokenEndpoint, _ := authMetadata["token_endpoint"].(string)
	registrationEndpoint, _ := authMetadata["registration_endpoint"].(string)
	if authorizationEndpoint == "" || tokenEndpoint == "" {
		return nil, fmt.Errorf("authorization metadata missing required endpoints")
	}

	scopes := make([]string, 0)
	if supportedScopes, ok := resourceMetadata["scopes_supported"].([]any); ok {
		for _, value := range supportedScopes {
			scope, ok := value.(string)
			if ok && strings.TrimSpace(scope) != "" {
				scopes = append(scopes, scope)
			}
		}
	}

	resource, _ := resourceMetadata["resource"].(string)

	return &mcpOAuthDiscovery{
		authorizationEndpoint: authorizationEndpoint,
		tokenEndpoint:         tokenEndpoint,
		registrationEndpoint:  registrationEndpoint,
		resource:              resource,
		scopes:                scopes,
	}, nil
}

func (s *Service) registerOAuthClient(discovery *mcpOAuthDiscovery, redirectURI string) (string, error) {
	if discovery.registrationEndpoint == "" {
		return "", fmt.Errorf("authorization server does not expose a registration endpoint")
	}

	body := map[string]any{
		"client_name":               "Wacht MCP Client",
		"redirect_uris":             []string{redirectURI},
		"grant_types":               []string{"authorization_code"},
		"response_types":            []string{"code"},
		"token_endpoint_auth_method": "none",
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("failed to marshal registration request: %w", err)
	}

	request, err := http.NewRequest(http.MethodPost, discovery.registrationEndpoint, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return "", fmt.Errorf("failed to build registration request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{Timeout: 12 * time.Second}
	response, err := httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("failed to register OAuth client: %w", err)
	}
	defer response.Body.Close()

	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read registration response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("client registration failed (%d): %s", response.StatusCode, string(raw))
	}

	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("failed to parse registration response: %w", err)
	}
	clientID, _ := payload["client_id"].(string)
	if clientID == "" {
		return "", fmt.Errorf("registration response missing client_id")
	}
	return clientID, nil
}

func (s *Service) exchangeMcpAuthorizationCode(
	state mcpOAuthState,
	code string,
	clientSecret *string,
) (map[string]any, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", state.ClientID)
	form.Set("code", code)
	form.Set("redirect_uri", state.RedirectURI)
	form.Set("code_verifier", state.CodeVerifier)
	if strings.TrimSpace(state.Resource) != "" {
		form.Set("resource", state.Resource)
	}

	request, err := http.NewRequest(http.MethodPost, state.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to build token exchange request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientSecret != nil && strings.TrimSpace(*clientSecret) != "" {
		request.SetBasicAuth(state.ClientID, *clientSecret)
	}

	httpClient := &http.Client{Timeout: 12 * time.Second}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token exchange response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("token exchange failed (%d): %s", response.StatusCode, string(body))
	}

	var tokenPayload map[string]any
	if err := json.Unmarshal(body, &tokenPayload); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	return tokenPayload, nil
}

func (s *Service) GetActiveMcpServers(deploymentID uint64, agentName, contextGroup string) ([]AgentMcpServer, error) {
	type activeMcpServersRow struct {
		McpServersJSON json.RawMessage `gorm:"column:mcp_servers_json"`
	}

	var row activeMcpServersRow
	if err := s.db.Raw(`
		WITH target_agent AS (
			SELECT id
			FROM ai_agents
			WHERE deployment_id = ? AND name = ?
			LIMIT 1
		),
		attached_servers AS (
			SELECT
				m.id,
				m.name,
				(
					COALESCE(m.config->'auth'->>'type', '') IN (
						'oauth_authorization_code_public_pkce',
						'oauth_authorization_code_confidential_pkce'
					)
				) AS requires_connection
			FROM ai_agent_mcp_servers ams
			JOIN target_agent ta ON ta.id = ams.agent_id
			JOIN mcp_servers m
				ON m.id = ams.mcp_server_id
				AND m.deployment_id = ams.deployment_id
			WHERE ams.deployment_id = ?
		),
		active_links AS (
			SELECT aams.mcp_server_id
			FROM active_agent_mcp_servers aams
			JOIN target_agent ta ON ta.id = aams.agent_id
			WHERE aams.deployment_id = ?
				AND aams.context_group = ?
		)
		SELECT COALESCE(json_agg(
			json_build_object(
				'id', s.id::text,
				'name', s.name,
				'requires_connection', s.requires_connection
			)
			ORDER BY s.name ASC
		), '[]'::json) AS mcp_servers_json
		FROM attached_servers s
		WHERE s.requires_connection = FALSE
			OR EXISTS (
				SELECT 1
				FROM active_links al
				WHERE al.mcp_server_id = s.id
			)
	`, deploymentID, agentName, deploymentID, deploymentID, contextGroup).Scan(&row).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch active MCP servers: %w", err)
	}

	var active []AgentMcpServer
	if len(row.McpServersJSON) == 0 {
		return []AgentMcpServer{}, nil
	}
	if err := json.Unmarshal(row.McpServersJSON, &active); err != nil {
		return nil, fmt.Errorf("failed to parse active MCP servers: %w", err)
	}

	return active, nil
}

func (s *Service) ConnectMcpServer(
	deploymentID uint64,
	sessionID uint64,
	agentName,
	contextGroup string,
	mcpServerID uint64,
	callbackURL string,
	redirectBackURL string,
) (*McpConnectResult, error) {
	var agent model.AiAgent
	if err := s.db.Where("deployment_id = ? AND name = ?", deploymentID, agentName).First(&agent).Error; err != nil {
		return nil, fmt.Errorf("agent not found: %w", err)
	}

	var relation model.AiAgentMcpServer
	if err := s.db.Where("deployment_id = ? AND agent_id = ? AND mcp_server_id = ?", deploymentID, agent.ID, mcpServerID).
		First(&relation).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("MCP server is not attached to this agent")
		}
		return nil, fmt.Errorf("failed to validate MCP server relation: %w", err)
	}

	var mcpServer model.McpServer
	if err := s.db.Where("id = ? AND deployment_id = ?", mcpServerID, deploymentID).First(&mcpServer).Error; err != nil {
		return nil, fmt.Errorf("MCP server not found: %w", err)
	}

	var authType model.McpServerAuthType
	if mcpServer.Config.Auth != nil {
		authType = mcpServer.Config.Auth.Type
	}

	requiresOAuth := authType == model.McpServerAuthTypeOAuthAuthorizationCodePublicPKCE ||
		authType == model.McpServerAuthTypeOAuthAuthorizationCodeConfidentialPKCE

	if requiresOAuth {
		if mcpServer.Config.Auth == nil {
			return nil, fmt.Errorf("MCP server OAuth configuration is missing")
		}

		clientID := ""
		if mcpServer.Config.Auth.ClientID != nil {
			clientID = strings.TrimSpace(*mcpServer.Config.Auth.ClientID)
		}
		if clientID == "" {
			return nil, fmt.Errorf("MCP server OAuth configuration is missing client_id")
		}

		authURLRaw := ""
		if mcpServer.Config.Auth.AuthURL != nil {
			authURLRaw = strings.TrimSpace(*mcpServer.Config.Auth.AuthURL)
		}
		if authURLRaw == "" {
			return nil, fmt.Errorf("MCP server OAuth configuration is missing auth_url")
		}

		tokenURLRaw := ""
		if mcpServer.Config.Auth.TokenURL != nil {
			tokenURLRaw = strings.TrimSpace(*mcpServer.Config.Auth.TokenURL)
		}
		if tokenURLRaw == "" {
			return nil, fmt.Errorf("MCP server OAuth configuration is missing token_url")
		}

		resource := ""
		if mcpServer.Config.Auth.Resource != nil {
			resource = strings.TrimSpace(*mcpServer.Config.Auth.Resource)
		}
		scopes := append([]string{}, mcpServer.Config.Auth.Scopes...)

		codeVerifier, err := randomPKCEVerifier()
		if err != nil {
			return nil, fmt.Errorf("failed to generate PKCE verifier: %w", err)
		}
		stateNonce, err := randomURLSafe(32)
		if err != nil {
			return nil, fmt.Errorf("failed to generate state nonce: %w", err)
		}

		oauthState := mcpOAuthState{
			DeploymentID: deploymentID,
			SessionID:    sessionID,
			AgentID:      agent.ID,
			McpServerID:  mcpServerID,
			ContextGroup: contextGroup,
			CodeVerifier: codeVerifier,
			ClientID:     clientID,
			TokenURL:     tokenURLRaw,
			RedirectURI:  callbackURL,
			Resource:     resource,
			RedirectBack: redirectBackURL,
		}
		statePayload, err := json.Marshal(oauthState)
		if err != nil {
			return nil, fmt.Errorf("failed to encode OAuth state: %w", err)
		}

		stateKey := fmt.Sprintf("mcp:oauth:state:%s", stateNonce)
		if err := database.Redis.Set(context.Background(), stateKey, statePayload, 15*time.Minute).Err(); err != nil {
			return nil, fmt.Errorf("failed to store OAuth state: %w", err)
		}

		authURL, err := url.Parse(authURLRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid authorization endpoint: %w", err)
		}
		query := authURL.Query()
		query.Set("response_type", "code")
		query.Set("client_id", clientID)
		query.Set("redirect_uri", callbackURL)
		query.Set("state", stateNonce)
		query.Set("code_challenge", pkceChallenge(codeVerifier))
		query.Set("code_challenge_method", "S256")
		if len(scopes) > 0 {
			query.Set("scope", strings.Join(scopes, " "))
		}
		if resource != "" {
			query.Set("resource", resource)
		}
		authURL.RawQuery = query.Encode()

		return &McpConnectResult{
			RequiresOAuth: true,
			OAuthURL:      authURL.String(),
		}, nil
	}

	return &McpConnectResult{
		RequiresOAuth: false,
	}, nil
}

func (s *Service) DisconnectMcpServer(deploymentID uint64, agentName, contextGroup string, mcpServerID uint64) error {
	var agent model.AiAgent
	if err := s.db.Where("deployment_id = ? AND name = ?", deploymentID, agentName).First(&agent).Error; err != nil {
		return fmt.Errorf("agent not found: %w", err)
	}

	var mcpServer model.McpServer
	if err := s.db.Where("id = ? AND deployment_id = ?", mcpServerID, deploymentID).First(&mcpServer).Error; err != nil {
		return fmt.Errorf("MCP server not found: %w", err)
	}
	if mcpServer.Config.Auth == nil {
		return nil
	}
	if mcpServer.Config.Auth.Type != model.McpServerAuthTypeOAuthAuthorizationCodePublicPKCE &&
		mcpServer.Config.Auth.Type != model.McpServerAuthTypeOAuthAuthorizationCodeConfidentialPKCE {
		return nil
	}

	return s.db.
		Where("deployment_id = ? AND context_group = ? AND agent_id = ? AND mcp_server_id = ?",
			deploymentID, contextGroup, agent.ID, mcpServerID).
		Delete(&model.ActiveAgentMcpServer{}).Error
}

func (s *Service) CompleteMcpOAuthConnection(
	deploymentID uint64,
	sessionID uint64,
	stateNonce string,
	code string,
) (string, error) {
	stateKey := fmt.Sprintf("mcp:oauth:state:%s", stateNonce)
	stateRaw, err := database.Redis.Get(context.Background(), stateKey).Bytes()
	if err != nil {
		return "", fmt.Errorf("invalid or expired OAuth state")
	}
	_ = database.Redis.Del(context.Background(), stateKey).Err()

	var state mcpOAuthState
	if err := json.Unmarshal(stateRaw, &state); err != nil {
		return "", fmt.Errorf("failed to parse OAuth state: %w", err)
	}

	if state.DeploymentID != deploymentID || state.SessionID != sessionID {
		return "", fmt.Errorf("OAuth state does not match current session")
	}

	var mcpServer model.McpServer
	if err := s.db.Where("id = ? AND deployment_id = ?", state.McpServerID, state.DeploymentID).First(&mcpServer).Error; err != nil {
		return "", fmt.Errorf("MCP server not found while completing OAuth: %w", err)
	}

	var clientSecret *string
	authType := string(model.McpServerAuthTypeOAuthAuthorizationCodePublicPKCE)
	if mcpServer.Config.Auth != nil {
		authType = string(mcpServer.Config.Auth.Type)
		if mcpServer.Config.Auth.Type == model.McpServerAuthTypeOAuthAuthorizationCodeConfidentialPKCE {
			clientSecret = mcpServer.Config.Auth.ClientSecret
		}
	}

	tokenPayload, err := s.exchangeMcpAuthorizationCode(state, code, clientSecret)
	if err != nil {
		return "", err
	}

	accessToken, _ := tokenPayload["access_token"].(string)
	if strings.TrimSpace(accessToken) == "" {
		return "", fmt.Errorf("token response missing access_token")
	}
	refreshToken, _ := tokenPayload["refresh_token"].(string)
	tokenType, _ := tokenPayload["token_type"].(string)
	scope, _ := tokenPayload["scope"].(string)
	expiresAt := parseTokenExpiry(tokenPayload["expires_in"])

	connectionMetadata := map[string]any{
		"auth_type":      authType,
		"access_token":   accessToken,
		"refresh_token":  refreshToken,
		"token_type":     tokenType,
		"scope":          scope,
		"token_url":      state.TokenURL,
		"resource":       state.Resource,
		"connected_at":   time.Now().UTC(),
		"oauth_client_id": state.ClientID,
	}
	if expiresAt != nil {
		connectionMetadata["expires_at"] = expiresAt
	}

	connectionJSON, err := json.Marshal(connectionMetadata)
	if err != nil {
		return "", fmt.Errorf("failed to encode connection metadata: %w", err)
	}

	if err := s.db.Exec(`
		INSERT INTO active_agent_mcp_servers
			(deployment_id, context_group, agent_id, mcp_server_id, connection_metadata, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?::jsonb, NOW(), NOW())
		ON CONFLICT (deployment_id, context_group, agent_id, mcp_server_id)
		DO UPDATE SET connection_metadata = EXCLUDED.connection_metadata, updated_at = NOW()
	`, state.DeploymentID, state.ContextGroup, state.AgentID, state.McpServerID, string(connectionJSON)).Error; err != nil {
		return "", fmt.Errorf("failed to persist MCP OAuth connection: %w", err)
	}

	return state.RedirectBack, nil
}
