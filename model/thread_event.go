package model

import (
	"encoding/json"
	"time"
)

type ThreadEvent struct {
	Model
	DeploymentID           uint64          `json:"deployment_id,string" gorm:"not null;index"`
	ThreadID               uint64          `json:"thread_id,string" gorm:"not null;index"`
	BoardItemID            *uint64         `json:"board_item_id,omitempty,string" gorm:"column:board_item_id"`
	EventType              string          `json:"event_type" gorm:"not null"`
	Status                 string          `json:"status" gorm:"not null"`
	Priority               int             `json:"priority" gorm:"not null;default:100"`
	Payload                json.RawMessage `json:"payload" gorm:"type:jsonb;not null"`
	AvailableAt            time.Time       `json:"available_at" gorm:"not null"`
	ClaimedAt              *time.Time      `json:"claimed_at,omitempty"`
	CompletedAt            *time.Time      `json:"completed_at,omitempty"`
	FailedAt               *time.Time      `json:"failed_at,omitempty"`
	CausedByConversationID *uint64         `json:"caused_by_conversation_id,omitempty,string" gorm:"column:caused_by_conversation_id"`
	CausedByRunID          *uint64         `json:"caused_by_run_id,omitempty,string" gorm:"column:caused_by_run_id"`
	CausedByThreadID       *uint64         `json:"caused_by_thread_id,omitempty,string" gorm:"column:caused_by_thread_id"`
}

func (ThreadEvent) TableName() string {
	return "thread_events"
}
