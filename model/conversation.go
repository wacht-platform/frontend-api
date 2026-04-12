package model

import (
	"encoding/json"
	"time"
)

type Conversation struct {
	ID             uint64          `json:"id,string"           gorm:"primaryKey;autoIncrement"`
	ThreadID       uint64          `json:"thread_id,string"    gorm:"column:thread_id;not null;index"`
	ExecutionRunID *uint64         `json:"execution_run_id,omitempty,string" gorm:"column:execution_run_id"`
	Timestamp      time.Time       `json:"timestamp"           gorm:"not null"`
	Content        json.RawMessage `json:"content"             gorm:"type:jsonb;not null"`
	MessageType    string          `json:"message_type"        gorm:"not null"`
	Metadata       json.RawMessage `json:"metadata,omitempty"  gorm:"type:jsonb"`
	CreatedAt      time.Time       `json:"created_at"          gorm:"not null;default:CURRENT_TIMESTAMP"`
	UpdatedAt      time.Time       `json:"updated_at"          gorm:"not null;default:CURRENT_TIMESTAMP"`
}

func (Conversation) TableName() string {
	return "conversations"
}
