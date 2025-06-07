package model

import (
	"database/sql/driver"
	"gorm.io/datatypes"
)

// =============================================================================
// AI TOOL TYPES AND MAIN MODEL
// =============================================================================

// AIToolType represents the type of AI tool
type AIToolType string

const (
	AIToolTypeAPI           AIToolType = "api"
	AIToolTypeKnowledgeBase AIToolType = "knowledge_base"
)

func (t *AIToolType) Scan(value any) error {
	*t = AIToolType(value.(string))
	return nil
}

func (t AIToolType) Value() (driver.Value, error) {
	return string(t), nil
}

// HTTPMethod represents HTTP methods for API tools
type HTTPMethod string

const (
	HTTPMethodGET    HTTPMethod = "GET"
	HTTPMethodPOST   HTTPMethod = "POST"
	HTTPMethodPUT    HTTPMethod = "PUT"
	HTTPMethodDELETE HTTPMethod = "DELETE"
	HTTPMethodPATCH  HTTPMethod = "PATCH"
)

func (m *HTTPMethod) Scan(value any) error {
	*m = HTTPMethod(value.(string))
	return nil
}

func (m HTTPMethod) Value() (driver.Value, error) {
	return string(m), nil
}

type AITool struct {
	Model
	Name           string            `json:"name"           gorm:"not null"`
	Description    *string           `json:"description"`
	ToolType       AIToolType        `json:"tool_type"      gorm:"not null"`
	DeploymentID   uint64            `json:"deployment_id"  gorm:"not null;index"`
	Deployment     Deployment        `json:"-"              gorm:"foreignKey:DeploymentID"`
	Configuration  datatypes.JSONMap `json:"configuration"  gorm:"not null;default:'{}'"`

	// Relationships
	Agents []AIAgent `json:"agents,omitempty" gorm:"many2many:ai_agent_tools;"`
}

// AIToolWithDetails includes additional details for API responses
type AIToolWithDetails struct {
	AITool
	// Add any additional fields that might be needed for detailed responses
}

// =============================================================================
// AI TOOL CONFIGURATION
// =============================================================================

// AIToolConfiguration represents the configuration for different types of AI tools
// This matches the Rust enum structure with tagged unions
type AIToolConfiguration struct {
	Type string `json:"type"` // "api" or "knowledge_base"

	// API Tool Configuration (when Type == "api")
	API *APIToolConfiguration `json:"api,omitempty"`

	// Knowledge Base Tool Configuration (when Type == "knowledge_base")
	KnowledgeBase *KnowledgeBaseToolConfiguration `json:"knowledge_base,omitempty"`
}

// APIToolConfiguration represents configuration for API-based tools
type APIToolConfiguration struct {
	Endpoint        string                        `json:"endpoint"`
	Method          HTTPMethod                    `json:"method"`
	Headers         []HTTPParameter               `json:"headers"`
	QueryParameters []HTTPParameter               `json:"query_parameters"`
	BodyParameters  []HTTPParameter               `json:"body_parameters"`
	Authorization   *AuthorizationConfiguration   `json:"authorization,omitempty"`
}

// KnowledgeBaseToolConfiguration represents configuration for knowledge base tools
type KnowledgeBaseToolConfiguration struct {
	KnowledgeBaseID uint64                        `json:"knowledge_base_id,string"`
	SearchSettings  KnowledgeBaseSearchSettings   `json:"search_settings"`
}

// KnowledgeBaseSearchSettings represents search configuration for knowledge base tools
type KnowledgeBaseSearchSettings struct {
	MaxResults          *uint32 `json:"max_results,omitempty"`
	SimilarityThreshold *float32 `json:"similarity_threshold,omitempty"`
	IncludeMetadata     bool    `json:"include_metadata"`
}

// HTTPParameter represents a parameter for HTTP requests
type HTTPParameter struct {
	Name        string              `json:"name"`
	ValueType   ParameterValueType  `json:"value_type"`
	Required    bool                `json:"required"`
	Description *string             `json:"description,omitempty"`
}

// ParameterValueType represents how parameter values are determined
type ParameterValueType struct {
	Type string `json:"type"` // "hardcoded" or "from_chat"

	// For hardcoded values
	Value *string `json:"value,omitempty"`

	// For values from chat context
	LookupKey *string `json:"lookup_key,omitempty"`
}

// AuthorizationConfiguration represents authorization settings for API tools
type AuthorizationConfiguration struct {
	AuthorizeAsUser   bool              `json:"authorize_as_user"`
	JWTTemplateID     *uint64           `json:"jwt_template_id,string,omitempty"`
	CustomHeaders     []HTTPParameter   `json:"custom_headers"`
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// NewAPIToolConfiguration creates a new API tool configuration with defaults
func NewAPIToolConfiguration(endpoint string, method HTTPMethod) *AIToolConfiguration {
	return &AIToolConfiguration{
		Type: "api",
		API: &APIToolConfiguration{
			Endpoint:        endpoint,
			Method:          method,
			Headers:         []HTTPParameter{},
			QueryParameters: []HTTPParameter{},
			BodyParameters:  []HTTPParameter{},
		},
	}
}

// NewKnowledgeBaseToolConfiguration creates a new knowledge base tool configuration with defaults
func NewKnowledgeBaseToolConfiguration(knowledgeBaseID uint64) *AIToolConfiguration {
	maxResults := uint32(10)
	threshold := float32(0.7)

	return &AIToolConfiguration{
		Type: "knowledge_base",
		KnowledgeBase: &KnowledgeBaseToolConfiguration{
			KnowledgeBaseID: knowledgeBaseID,
			SearchSettings: KnowledgeBaseSearchSettings{
				MaxResults:          &maxResults,
				SimilarityThreshold: &threshold,
				IncludeMetadata:     true,
			},
		},
	}
}

// NewHardcodedParameter creates a parameter with a hardcoded value
func NewHardcodedParameter(name, value string, required bool, description *string) HTTPParameter {
	return HTTPParameter{
		Name: name,
		ValueType: ParameterValueType{
			Type:  "hardcoded",
			Value: &value,
		},
		Required:    required,
		Description: description,
	}
}

// NewChatParameter creates a parameter that gets its value from chat context
func NewChatParameter(name, lookupKey string, required bool, description *string) HTTPParameter {
	return HTTPParameter{
		Name: name,
		ValueType: ParameterValueType{
			Type:      "from_chat",
			LookupKey: &lookupKey,
		},
		Required:    required,
		Description: description,
	}
}
