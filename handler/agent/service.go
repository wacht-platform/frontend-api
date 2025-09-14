package agent

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/godruoyi/go-snowflake"
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

func (s *Service) CreateContext(deploymentID uint64, contextGroup *string, req CreateContextRequest) (*model.AgentExecutionContext, error) {
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

func (s *Service) ListContexts(deploymentID uint64, contextGroup *string, params ListContextsRequest) (*ListContextsResponse, error) {
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

func (s *Service) GetContext(deploymentID uint64, contextGroup *string, contextID uint64) (*model.AgentExecutionContext, error) {
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

func (s *Service) GetContextMessages(deploymentID uint64, contextGroup *string, contextID uint64, limit int, beforeID, afterID string) ([]ConversationMessage, bool, error) {
	// First verify the context exists and user has access
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

	// Now fetch messages from conversations table
	messagesQuery := s.db.Model(&model.Conversation{}).
		Where("context_id = ?", contextID).
		Where("message_type != ?", "execution_summary")

	// Apply pagination
	if beforeID != "" {
		messagesQuery = messagesQuery.Where("id < ?", beforeID)
	}
	if afterID != "" {
		messagesQuery = messagesQuery.Where("id > ?", afterID).Order("id ASC")
	} else {
		messagesQuery = messagesQuery.Order("id DESC")
	}

	// Fetch limit + 1 to check if there are more
	messagesQuery = messagesQuery.Limit(limit + 1)

	var conversations []model.Conversation
	if err := messagesQuery.Find(&conversations).Error; err != nil {
		return nil, false, fmt.Errorf("failed to fetch messages: %w", err)
	}

	hasMore := len(conversations) > limit
	if hasMore {
		conversations = conversations[:limit]
	}

	// If we fetched in ascending order (afterID), reverse to maintain chronological order
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
		case "agent_response", "assistant_acknowledgment", "assistant_ideation",
			"assistant_action_planning", "action_execution_result", "assistant_validation":
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
