package model

import (
	"database/sql/driver"
	"time"

	"gorm.io/datatypes"
)

type WorkflowStatus string

const (
	WorkflowStatusDraft    WorkflowStatus = "draft"
	WorkflowStatusActive   WorkflowStatus = "active"
	WorkflowStatusInactive WorkflowStatus = "inactive"
	WorkflowStatusArchived WorkflowStatus = "archived"
)

func (s *WorkflowStatus) Scan(value any) error {
	*s = WorkflowStatus(value.(string))
	return nil
}

func (s WorkflowStatus) Value() (driver.Value, error) {
	return string(s), nil
}

type AIWorkflow struct {
	Model
	Name               string                `json:"name"                  gorm:"not null"`
	Description        *string               `json:"description"`
	DeploymentID       uint64                `json:"deployment_id"         gorm:"not null;index"`
	Deployment         Deployment            `json:"-"                     gorm:"foreignKey:DeploymentID"`
	Status             WorkflowStatus        `json:"status"                gorm:"not null;default:'draft'"`
	Configuration      datatypes.JSONMap     `json:"configuration"         gorm:"not null;default:'{}'"`
	WorkflowDefinition datatypes.JSONMap     `json:"workflow_definition"   gorm:"not null;default:'{}'"`
	Agents             []AIAgent             `json:"agents,omitempty"     gorm:"many2many:ai_agent_workflows;"`
	Executions         []AIWorkflowExecution `json:"executions,omitempty" gorm:"foreignKey:WorkflowID;constraint:OnDelete:CASCADE;"`
}

type AIWorkflowWithDetails struct {
	AIWorkflow
	ExecutionsCount uint64     `json:"executions_count"`
	LastExecution   *time.Time `json:"last_execution,omitempty"`
}

type WorkflowConfiguration struct {
	TimeoutSeconds    *uint32                     `json:"timeout_seconds,omitempty"`
	MaxRetries        *uint32                     `json:"max_retries,omitempty"`
	RetryDelaySeconds *uint32                     `json:"retry_delay_seconds,omitempty"`
	EnableLogging     bool                        `json:"enable_logging"`
	EnableMetrics     bool                        `json:"enable_metrics"`
	Variables         map[string]WorkflowVariable `json:"variables"`
}

type WorkflowVariable struct {
	Name         string       `json:"name"`
	ValueType    VariableType `json:"value_type"`
	DefaultValue *string      `json:"default_value,omitempty"`
	Description  *string      `json:"description,omitempty"`
	Required     bool         `json:"required"`
}

type VariableType string

const (
	VariableTypeString  VariableType = "string"
	VariableTypeNumber  VariableType = "number"
	VariableTypeBoolean VariableType = "boolean"
	VariableTypeObject  VariableType = "object"
	VariableTypeArray   VariableType = "array"
)

type WorkflowDefinition struct {
	Nodes   []WorkflowNode `json:"nodes"`
	Edges   []WorkflowEdge `json:"edges"`
	Version string         `json:"version"`
}

type WorkflowNode struct {
	ID       string           `json:"id"`
	NodeType WorkflowNodeType `json:"node_type"`
	Position NodePosition     `json:"position"`
	Data     WorkflowNodeData `json:"data"`
}

type NodePosition struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

type WorkflowNodeData struct {
	Label       string      `json:"label"`
	Description *string     `json:"description,omitempty"`
	Enabled     bool        `json:"enabled"`
	Config      interface{} `json:"config"`
}

type WorkflowEdge struct {
	ID           string         `json:"id"`
	Source       string         `json:"source"`
	Target       string         `json:"target"`
	SourceHandle *string        `json:"source_handle,omitempty"`
	TargetHandle *string        `json:"target_handle,omitempty"`
	Condition    *EdgeCondition `json:"condition,omitempty"`
}

type EdgeCondition struct {
	Expression    string        `json:"expression"`
	ConditionType ConditionType `json:"condition_type"`
}

type ConditionType string

const (
	ConditionTypeAlways      ConditionType = "always"
	ConditionTypeOnSuccess   ConditionType = "on_success"
	ConditionTypeOnError     ConditionType = "on_error"
	ConditionTypeOnCondition ConditionType = "on_condition"
)

// WorkflowNodeType represents the type of workflow node with tagged union structure
// This matches Rust's #[serde(tag = "type")] behavior exactly
type WorkflowNodeType struct {
	Type string `json:"type"`

	// Only one of these will be populated based on the Type field
	*TriggerNodeConfig   `json:",inline,omitempty"`
	*ActionNodeConfig    `json:",inline,omitempty"`
	*ConditionNodeConfig `json:",inline,omitempty"`
	*TransformNodeConfig `json:",inline,omitempty"`
}

type TriggerNodeConfig struct {
	TriggerType   TriggerType    `json:"trigger_type"`
	ScheduledAt   *time.Time     `json:"scheduled_at,omitempty"` // Future date for scheduled triggers
	WebhookConfig *WebhookConfig `json:"webhook_config,omitempty"`
	EventConfig   *EventConfig   `json:"event_config,omitempty"`
}

type TriggerType string

const (
	TriggerTypeManual    TriggerType = "manual"
	TriggerTypeScheduled TriggerType = "scheduled"
	TriggerTypeWebhook   TriggerType = "webhook"
	TriggerTypeEvent     TriggerType = "event"
	TriggerTypeAPICall   TriggerType = "api_call"
)

type WebhookConfig struct {
	Endpoint       string            `json:"endpoint"`
	Method         string            `json:"method"`
	Headers        map[string]string `json:"headers"`
	Authentication *WebhookAuth      `json:"authentication,omitempty"`
}

type WebhookAuth struct {
	AuthType string  `json:"auth_type"`
	Token    *string `json:"token,omitempty"`
	Username *string `json:"username,omitempty"`
	Password *string `json:"password,omitempty"`
}

type EventConfig struct {
	EventType string            `json:"event_type"`
	Filters   map[string]string `json:"filters"`
}

type ActionNodeConfig struct {
	ActionType            ActionType                   `json:"action_type"`
	ToolID                *uint64                      `json:"tool_id,string,omitempty"`
	APIConfig             *APIActionConfig             `json:"api_config,omitempty"`
	KnowledgeBaseConfig   *KnowledgeBaseActionConfig   `json:"knowledge_base_config,omitempty"`
	TriggerWorkflowConfig *TriggerWorkflowActionConfig `json:"trigger_workflow_config,omitempty"`
}

type ActionType string

const (
	ActionTypeAPICall             ActionType = "api_call"
	ActionTypeKnowledgeBaseSearch ActionType = "knowledge_base_search"
	ActionTypeTriggerWorkflow     ActionType = "trigger_workflow"
)

type APIActionConfig struct {
	Endpoint       string            `json:"endpoint"`
	Method         string            `json:"method"`
	Headers        map[string]string `json:"headers"`
	Body           *string           `json:"body,omitempty"`
	TimeoutSeconds *uint32           `json:"timeout_seconds,omitempty"`
}

type KnowledgeBaseActionConfig struct {
	KnowledgeBaseID     uint64   `json:"knowledge_base_id,string"`
	Query               string   `json:"query"`
	MaxResults          *uint32  `json:"max_results,omitempty"`
	SimilarityThreshold *float32 `json:"similarity_threshold,omitempty"`
}

type TriggerWorkflowActionConfig struct {
	TargetWorkflowID  uint64            `json:"target_workflow_id,string"`
	InputMapping      map[string]string `json:"input_mapping"`
	WaitForCompletion bool              `json:"wait_for_completion"`
	TimeoutSeconds    *uint32           `json:"timeout_seconds,omitempty"`
}

type ConditionNodeConfig struct {
	ConditionType ConditionEvaluationType `json:"condition_type"`
	Expression    string                  `json:"expression"`
	TruePath      *string                 `json:"true_path,omitempty"`
	FalsePath     *string                 `json:"false_path,omitempty"`
}

type ConditionEvaluationType string

const (
	ConditionEvaluationTypeJavaScript ConditionEvaluationType = "javascript"
	ConditionEvaluationTypeJSONPath   ConditionEvaluationType = "json_path"
	ConditionEvaluationTypeSimple     ConditionEvaluationType = "simple"
)

type TransformNodeConfig struct {
	TransformType TransformType     `json:"transform_type"`
	Script        string            `json:"script"`
	InputMapping  map[string]string `json:"input_mapping"`
	OutputMapping map[string]string `json:"output_mapping"`
}

type TransformType string

const (
	TransformTypeJavaScript    TransformType = "javascript"
	TransformTypeJSONTransform TransformType = "json_transform"
	TransformTypeDataMapping   TransformType = "data_mapping"
)

type ExecutionStatus string

const (
	ExecutionStatusPending   ExecutionStatus = "pending"
	ExecutionStatusRunning   ExecutionStatus = "running"
	ExecutionStatusCompleted ExecutionStatus = "completed"
	ExecutionStatusFailed    ExecutionStatus = "failed"
	ExecutionStatusCancelled ExecutionStatus = "cancelled"
	ExecutionStatusTimeout   ExecutionStatus = "timeout"
)

func (s *ExecutionStatus) Scan(value any) error {
	*s = ExecutionStatus(value.(string))
	return nil
}

func (s ExecutionStatus) Value() (driver.Value, error) {
	return string(s), nil
}

type AIWorkflowExecution struct {
	Model
	WorkflowID       uint64            `json:"workflow_id,string"    gorm:"not null;index"`
	Workflow         AIWorkflow        `json:"workflow"              gorm:"foreignKey:WorkflowID;constraint:OnDelete:CASCADE"`
	Status           ExecutionStatus   `json:"status"                gorm:"not null;default:'pending'"`
	TriggerData      datatypes.JSON    `json:"trigger_data"`
	ExecutionContext datatypes.JSONMap `json:"execution_context"     gorm:"not null;default:'{}'"`
	OutputData       datatypes.JSONMap `json:"output_data"           gorm:"not null;default:'{}'"`
	StartedAt        *time.Time        `json:"started_at"`
	CompletedAt      *time.Time        `json:"completed_at"`
	ErrorMessage     *string           `json:"error_message"`
}

type ExecutionContext struct {
	Variables      map[string]interface{} `json:"variables"`
	NodeExecutions []NodeExecution        `json:"node_executions"`
	CurrentNode    *string                `json:"current_node,omitempty"`
}

type NodeExecution struct {
	NodeID       string          `json:"node_id"`
	Status       ExecutionStatus `json:"status"`
	StartedAt    *time.Time      `json:"started_at,omitempty"`
	CompletedAt  *time.Time      `json:"completed_at,omitempty"`
	InputData    interface{}     `json:"input_data,omitempty"`
	OutputData   interface{}     `json:"output_data,omitempty"`
	ErrorMessage *string         `json:"error_message,omitempty"`
	RetryCount   uint32          `json:"retry_count"`
}

func NewWorkflowExecution(workflowID uint64, triggerData interface{}) *AIWorkflowExecution {
	var triggerJSON datatypes.JSON
	if triggerData != nil {
		if jsonBytes, ok := triggerData.([]byte); ok {
			triggerJSON = datatypes.JSON(jsonBytes)
		} else {
			triggerJSON = nil
		}
	}

	return &AIWorkflowExecution{
		Model: Model{
			ID: 0,
		},
		WorkflowID:  workflowID,
		Status:      ExecutionStatusPending,
		TriggerData: triggerJSON,
		ExecutionContext: datatypes.JSONMap{
			"variables":       make(map[string]interface{}),
			"node_executions": []NodeExecution{},
			"current_node":    nil,
		},
	}
}

func (e *AIWorkflowExecution) Start() {
	now := time.Now()
	e.Status = ExecutionStatusRunning
	e.StartedAt = &now
}

func (e *AIWorkflowExecution) Complete() {
	now := time.Now()
	e.Status = ExecutionStatusCompleted
	e.CompletedAt = &now
}

func (e *AIWorkflowExecution) Fail(errorMessage string) {
	now := time.Now()
	e.Status = ExecutionStatusFailed
	e.CompletedAt = &now
	e.ErrorMessage = &errorMessage
}

func (e *AIWorkflowExecution) Cancel() {
	now := time.Now()
	e.Status = ExecutionStatusCancelled
	e.CompletedAt = &now
}

func (e *AIWorkflowExecution) Timeout() {
	now := time.Now()
	e.Status = ExecutionStatusTimeout
	e.CompletedAt = &now
	errorMsg := "Execution timed out"
	e.ErrorMessage = &errorMsg
}

func (e *AIWorkflowExecution) GetDuration() *time.Duration {
	if e.StartedAt == nil {
		return nil
	}

	endTime := time.Now()
	if e.CompletedAt != nil {
		endTime = *e.CompletedAt
	}

	duration := endTime.Sub(*e.StartedAt)
	return &duration
}

func (e *AIWorkflowExecution) IsRunning() bool {
	return e.Status == ExecutionStatusRunning
}

func (e *AIWorkflowExecution) IsCompleted() bool {
	return e.Status == ExecutionStatusCompleted ||
		e.Status == ExecutionStatusFailed ||
		e.Status == ExecutionStatusCancelled ||
		e.Status == ExecutionStatusTimeout
}

func (e *AIWorkflowExecution) IsSuccessful() bool {
	return e.Status == ExecutionStatusCompleted
}

func NewNodeExecution(nodeID string) NodeExecution {
	now := time.Now()
	return NodeExecution{
		NodeID:     nodeID,
		Status:     ExecutionStatusPending,
		StartedAt:  &now,
		RetryCount: 0,
	}
}

func (ne *NodeExecution) Start() {
	now := time.Now()
	ne.Status = ExecutionStatusRunning
	ne.StartedAt = &now
}

func (ne *NodeExecution) Complete(outputData interface{}) {
	now := time.Now()
	ne.Status = ExecutionStatusCompleted
	ne.CompletedAt = &now
	ne.OutputData = outputData
}

func (ne *NodeExecution) Fail(errorMessage string) {
	now := time.Now()
	ne.Status = ExecutionStatusFailed
	ne.CompletedAt = &now
	ne.ErrorMessage = &errorMessage
}

func (ne *NodeExecution) IncrementRetry() {
	ne.RetryCount++
}

func NewTriggerNodeType(config TriggerNodeConfig) WorkflowNodeType {
	return WorkflowNodeType{
		Type:              "Trigger",
		TriggerNodeConfig: &config,
	}
}

func NewActionNodeType(config ActionNodeConfig) WorkflowNodeType {
	return WorkflowNodeType{
		Type:             "Action",
		ActionNodeConfig: &config,
	}
}

func NewConditionNodeType(config ConditionNodeConfig) WorkflowNodeType {
	return WorkflowNodeType{
		Type:                "Condition",
		ConditionNodeConfig: &config,
	}
}

func NewTransformNodeType(config TransformNodeConfig) WorkflowNodeType {
	return WorkflowNodeType{
		Type:                "Transform",
		TransformNodeConfig: &config,
	}
}

func NewDefaultWorkflowConfiguration() *WorkflowConfiguration {
	timeout := uint32(300) // 5 minutes
	maxRetries := uint32(3)
	retryDelay := uint32(5)

	return &WorkflowConfiguration{
		TimeoutSeconds:    &timeout,
		MaxRetries:        &maxRetries,
		RetryDelaySeconds: &retryDelay,
		EnableLogging:     true,
		EnableMetrics:     true,
		Variables:         make(map[string]WorkflowVariable),
	}
}

func NewDefaultWorkflowDefinition() *WorkflowDefinition {
	return &WorkflowDefinition{
		Nodes:   []WorkflowNode{},
		Edges:   []WorkflowEdge{},
		Version: "1.0.0",
	}
}

func NewWorkflowVariable(name string, valueType VariableType, required bool) WorkflowVariable {
	return WorkflowVariable{
		Name:      name,
		ValueType: valueType,
		Required:  required,
	}
}

func NewWorkflowNode(id, label string, nodeType WorkflowNodeType, x, y float64) WorkflowNode {
	return WorkflowNode{
		ID:       id,
		NodeType: nodeType,
		Position: NodePosition{X: x, Y: y},
		Data: WorkflowNodeData{
			Label:   label,
			Enabled: true,
		},
	}
}

func NewWorkflowEdge(id, source, target string) WorkflowEdge {
	return WorkflowEdge{
		ID:     id,
		Source: source,
		Target: target,
	}
}
