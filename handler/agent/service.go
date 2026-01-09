package agent

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/godruoyi/go-snowflake"
	"github.com/google/uuid"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"

	"gorm.io/gorm"
)

type Service struct {
	db *gorm.DB
}

func NewService() *Service {
	return &Service{
		db: database.Connection,
	}
}

func (s *Service) CreateContext(
	deploymentID uint64,
	contextGroup *string,
	req CreateContextRequest,
) (*model.AgentExecutionContext, error) {
	context := &model.AgentExecutionContext{
		Model: model.Model{
			ID: snowflake.ID(),
		},
		DeploymentID:       deploymentID,
		Title:              req.Title,
		SystemInstructions: req.SystemInstructions,
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
		Order("created_at DESC").
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

	messagesQuery := s.db.Model(&model.Conversation{}).
		Where("context_id = ?", contextID).
		Where("message_type != ?", "execution_summary")

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

func (s *Service) GetActiveIntegrations(deploymentID uint64, contextGroup string) ([]model.AgentIntegration, error) {
	var agent model.AiAgent
	if err := s.db.Where("deployment_id = ? AND name = ?", deploymentID, contextGroup).First(&agent).Error; err != nil {
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

func (s *Service) AddIntegration(deploymentID uint64, contextGroup string, integrationID uint64) error {
	var integration model.AgentIntegration
	if err := s.db.Where("id = ? AND deployment_id = ?", integrationID, deploymentID).First(&integration).Error; err != nil {
		return fmt.Errorf("integration not found or access denied")
	}

	var existing model.ActiveAgentIntegration
	err := s.db.Where("deployment_id = ? AND context_group = ? AND integration_id = ?",
		deploymentID, contextGroup, integrationID).First(&existing).Error
	if err == nil {
		return nil
	}

	active := model.ActiveAgentIntegration{
		Model: model.Model{
			ID: snowflake.ID(),
		},
		DeploymentID:  deploymentID,
		AgentID:       integration.AgentID,
		IntegrationID: integrationID,
		ContextGroup:  contextGroup,
	}

	if err := s.db.Create(&active).Error; err != nil {
		return fmt.Errorf("failed to add integration: %w", err)
	}

	return nil
}

func (s *Service) RemoveIntegration(deploymentID uint64, contextGroup string, integrationID uint64) error {
	result := s.db.Where("deployment_id = ? AND context_group = ? AND integration_id = ?",
		deploymentID, contextGroup, integrationID).Delete(&model.ActiveAgentIntegration{})

	if result.Error != nil {
		return fmt.Errorf("failed to remove integration: %w", result.Error)
	}

	return nil
}

func (s *Service) ListAvailableIntegrations(deploymentID uint64, contextGroup *string) ([]map[string]interface{}, error) {
	if contextGroup == nil || *contextGroup == "" {
		return nil, fmt.Errorf("context group (agent name) is required")
	}

	var agent model.AiAgent
	if err := s.db.Where("deployment_id = ? AND name = ?", deploymentID, *contextGroup).First(&agent).Error; err != nil {
		return nil, fmt.Errorf("agent not found: %w", err)
	}

	var integrations []model.AgentIntegration
	if err := s.db.Where("deployment_id = ? AND agent_id = ?", deploymentID, agent.ID).Find(&integrations).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch integrations: %w", err)
	}

	var activeIDs []uint64
	s.db.Model(&model.ActiveAgentIntegration{}).
		Where("deployment_id = ? AND agent_id = ? AND context_group = ?", deploymentID, agent.ID, *contextGroup).
		Pluck("integration_id", &activeIDs)

	activeSet := make(map[uint64]bool)
	for _, id := range activeIDs {
		activeSet[id] = true
	}

	result := make([]map[string]any, len(integrations))
	for i, integration := range integrations {
		result[i] = map[string]any{
			"id":               fmt.Sprintf("%d", integration.ID),
			"name":             integration.Name,
			"integration_type": integration.IntegrationType,
			"agent_id":         fmt.Sprintf("%d", integration.AgentID),
			"is_active":        activeSet[integration.ID],
		}
	}

	return result, nil
}

func (s *Service) GenerateLinkCode(deploymentID uint64, contextGroup string, integrationID uint64) (string, time.Time, error) {
	if contextGroup == "" {
		return "", time.Time{}, fmt.Errorf("context group (agent name) is required")
	}

	var integration model.AgentIntegration
	if err := s.db.Where("id = ? AND deployment_id = ?", integrationID, deploymentID).First(&integration).Error; err != nil {
		return "", time.Time{}, fmt.Errorf("integration not found or access denied")
	}

	code, err := generateAlphanumericCode(6)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to generate code: %w", err)
	}

	expiresAt := time.Now().Add(15 * time.Minute)

	linkCode := model.IntegrationLinkCode{
		ID:              snowflake.ID(),
		DeploymentID:    deploymentID,
		ContextGroup:    contextGroup,
		AgentID:         integration.AgentID,
		IntegrationType: integration.IntegrationType,
		Code:            code,
		ExpiresAt:       expiresAt,
	}

	if err := s.db.Create(&linkCode).Error; err != nil {
		return "", time.Time{}, fmt.Errorf("failed to save link code: %w", err)
	}

	return code, expiresAt, nil
}

func generateAlphanumericCode(length int) (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[num.Int64()]
	}
	return string(result), nil
}

func (s *Service) GenerateConsentURL(deploymentID uint64, contextGroup string, integrationID uint64, redirectURL string) (string, string, error) {
	// Get the integration to get appId from config
	var integration model.AgentIntegration
	if err := s.db.Where("id = ? AND deployment_id = ?", integrationID, deploymentID).First(&integration).Error; err != nil {
		return "", "", fmt.Errorf("integration not found")
	}

	// Parse config to get Teams App ID
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(integration.Config), &config); err != nil {
		return "", "", fmt.Errorf("invalid integration config")
	}

	appID, ok := config["app_id"].(string)
	if !ok || appID == "" {
		appID = os.Getenv("TEAMS_APP_ID")
	}
	if appID == "" {
		return "", "", fmt.Errorf("Teams App ID not configured")
	}

	// Generate state token
	state := uuid.New().String()

	// Store state in Redis with 15 minute TTL
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

	// Build consent URL
	callbackURL := os.Getenv("TEAMS_CONSENT_CALLBACK_URL")
	if callbackURL == "" {
		callbackURL = os.Getenv("AGENT_INTEGRATIONS_URL") + "/service/teams/consent/callback"
	}

	consentURL := fmt.Sprintf(
		"https://login.microsoftonline.com/common/adminconsent?client_id=%s&redirect_uri=%s&state=%s",
		appID,
		callbackURL,
		state,
	)

	return consentURL, state, nil
}
