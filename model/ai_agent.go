package model

import (
	"gorm.io/datatypes"
)

// =============================================================================
// AI AGENT MAIN MODEL
// =============================================================================

type AIAgent struct {
	Model
	Name           string            `json:"name"           gorm:"not null"`
	Description    *string           `json:"description"`
	DeploymentID   uint64            `json:"deployment_id"  gorm:"not null;index"`
	Deployment     Deployment        `json:"-"              gorm:"foreignKey:DeploymentID"`
	Configuration  datatypes.JSONMap `json:"configuration"  gorm:"not null;default:'{}'"`

	// Relationships
	Tools          []AITool          `json:"tools,omitempty"          gorm:"many2many:ai_agent_tools;"`
	Workflows      []AIWorkflow      `json:"workflows,omitempty"      gorm:"many2many:ai_agent_workflows;"`
	KnowledgeBases []AIKnowledgeBase `json:"knowledge_bases,omitempty" gorm:"many2many:ai_agent_knowledge_bases;"`
}

// =============================================================================
// AI AGENT CONFIGURATION
// =============================================================================

// AIAgentConfiguration represents the configuration for AI agents
type AIAgentConfiguration struct {
	// Model configuration
	Model       string   `json:"model"`                 // e.g., "gpt-4", "claude-3"
	Temperature *float32 `json:"temperature,omitempty"` // 0.0 to 1.0
	MaxTokens   *int     `json:"max_tokens,omitempty"`

	// System prompt and behavior
	SystemPrompt    string   `json:"system_prompt"`
	Instructions    []string `json:"instructions,omitempty"`

	// Capabilities
	CanUseTools         bool `json:"can_use_tools"`
	CanAccessKnowledge  bool `json:"can_access_knowledge"`
	CanExecuteWorkflows bool `json:"can_execute_workflows"`

	// Response settings
	ResponseFormat *ResponseFormat `json:"response_format,omitempty"`

	// Safety and moderation
	ContentFilter   *ContentFilter   `json:"content_filter,omitempty"`
	RateLimiting    *RateLimiting    `json:"rate_limiting,omitempty"`
}

// ResponseFormat defines how the agent should format responses
type ResponseFormat struct {
	Type        string            `json:"type"` // "text", "json", "markdown"
	Schema      map[string]any    `json:"schema,omitempty"` // JSON schema for structured responses
	Template    *string           `json:"template,omitempty"`
	Constraints *ResponseConstraints `json:"constraints,omitempty"`
}

// ResponseConstraints defines limits on agent responses
type ResponseConstraints struct {
	MaxLength     *int     `json:"max_length,omitempty"`
	RequiredFields []string `json:"required_fields,omitempty"`
	ForbiddenWords []string `json:"forbidden_words,omitempty"`
}

// ContentFilter defines content moderation settings
type ContentFilter struct {
	Enabled           bool     `json:"enabled"`
	BlockedCategories []string `json:"blocked_categories,omitempty"`
	CustomRules       []string `json:"custom_rules,omitempty"`
}

// RateLimiting defines rate limiting settings for the agent
type RateLimiting struct {
	RequestsPerMinute *int `json:"requests_per_minute,omitempty"`
	RequestsPerHour   *int `json:"requests_per_hour,omitempty"`
	RequestsPerDay    *int `json:"requests_per_day,omitempty"`
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// NewDefaultAgentConfiguration creates a basic agent configuration
func NewDefaultAgentConfiguration(model, systemPrompt string) *AIAgentConfiguration {
	temp := float32(0.7)
	maxTokens := 2048

	return &AIAgentConfiguration{
		Model:               model,
		Temperature:         &temp,
		MaxTokens:           &maxTokens,
		SystemPrompt:        systemPrompt,
		CanUseTools:         true,
		CanAccessKnowledge:  true,
		CanExecuteWorkflows: false,
		ResponseFormat: &ResponseFormat{
			Type: "text",
		},
		ContentFilter: &ContentFilter{
			Enabled: true,
		},
	}
}

// NewChatAgentConfiguration creates configuration optimized for chat interactions
func NewChatAgentConfiguration(systemPrompt string) *AIAgentConfiguration {
	config := NewDefaultAgentConfiguration("gpt-4", systemPrompt)
	config.Temperature = &[]float32{0.8}[0] // More creative for chat
	config.CanExecuteWorkflows = true

	return config
}

// NewAPIAgentConfiguration creates configuration optimized for API interactions
func NewAPIAgentConfiguration(systemPrompt string) *AIAgentConfiguration {
	config := NewDefaultAgentConfiguration("gpt-4", systemPrompt)
	config.Temperature = &[]float32{0.3}[0] // More deterministic for APIs
	config.ResponseFormat = &ResponseFormat{
		Type: "json",
	}

	return config
}
