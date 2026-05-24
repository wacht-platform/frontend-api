package model

import (
	"encoding/json"
	"time"
)

type TaskHandoffSummary struct {
	ID               uint64          `json:"id,string"                          gorm:"primaryKey;autoIncrement"`
	DeploymentID     uint64          `json:"deployment_id,string"               gorm:"not null;index"`
	BoardItemID      uint64          `json:"board_item_id,string"               gorm:"not null;index:idx_handoff_board_item_created,priority:1"`
	ThreadID         uint64          `json:"thread_id,string"                   gorm:"not null;index"`
	AssignmentID     *uint64         `json:"assignment_id,omitempty,string"`
	ExecutionRunID   *uint64         `json:"execution_run_id,omitempty,string"`
	AssignmentRole   string          `json:"assignment_role"                    gorm:"not null"`
	Outcome          string          `json:"outcome"                            gorm:"not null"`
	Summary          string          `json:"summary"                            gorm:"type:text;not null"`
	Artifacts        json.RawMessage `json:"artifacts,omitempty"                gorm:"type:jsonb"`
	Blockers         json.RawMessage `json:"blockers,omitempty"                 gorm:"type:jsonb"`
	NextActions      json.RawMessage `json:"next_actions,omitempty"             gorm:"type:jsonb"`
	Metadata         json.RawMessage `json:"metadata,omitempty"                 gorm:"type:jsonb"`
	CreatedAt        time.Time       `json:"created_at"                         gorm:"not null;default:CURRENT_TIMESTAMP;index:idx_handoff_board_item_created,priority:2,sort:desc"`
	UpdatedAt        time.Time       `json:"updated_at"                         gorm:"not null;default:CURRENT_TIMESTAMP"`
}

func (TaskHandoffSummary) TableName() string {
	return "task_handoff_summaries"
}
