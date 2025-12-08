package model

import (
	"database/sql/driver"
	"time"
)

type ExecutionContextStatus string

const (
	ExecutionStatusIdle            ExecutionContextStatus = "idle"
	ExecutionStatusRunning         ExecutionContextStatus = "running"
	ExecutionStatusWaitingForInput ExecutionContextStatus = "waiting_for_input"
	ExecutionStatusInterrupted     ExecutionContextStatus = "interrupted"
	ExecutionStatusCompleted       ExecutionContextStatus = "completed"
	ExecutionStatusFailed          ExecutionContextStatus = "failed"
)

func (s *ExecutionContextStatus) Scan(value any) error {
	*s = ExecutionContextStatus(value.(string))
	return nil
}

func (s ExecutionContextStatus) Value() (driver.Value, error) {
	return string(s), nil
}

// AgentExecutionContext database model - matches Rust table structure
type AgentExecutionContext struct {
	Model
	DeploymentID       uint64                 `json:"deployment_id,string"      gorm:"not null;index"`
	Title              string                 `json:"title"                     gorm:"not null"`
	SystemInstructions *string                `json:"system_instructions"       gorm:"type:text"`
	ContextGroup       *string                `json:"context_group"             gorm:"index"`
	LastActivityAt     time.Time              `json:"last_activity_at"          gorm:"not null;default:CURRENT_TIMESTAMP"`
	CompletedAt        *time.Time             `json:"completed_at"`
	Status             ExecutionContextStatus `json:"status"                    gorm:"not null;default:'idle'"`
	// ExecutionState stored as JSONB in PostgreSQL
	ExecutionState *string `json:"execution_state,omitempty" gorm:"type:jsonb"`
}

func (AgentExecutionContext) TableName() string {
	return "agent_execution_contexts"
}
