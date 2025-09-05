package model

import (
	"encoding/json"
	"time"
)

type Conversation struct {
	ID          uint64          `json:"id,string"     gorm:"primaryKey;autoIncrement"`
	ContextID   uint64          `json:"context_id,string" gorm:"not null;index"`
	Timestamp   time.Time       `json:"timestamp"     gorm:"not null"`
	Content     json.RawMessage `json:"content"       gorm:"type:jsonb;not null"`
	MessageType string          `json:"message_type"  gorm:"not null"`
	CreatedAt   time.Time       `json:"created_at"    gorm:"not null;default:CURRENT_TIMESTAMP"`
	UpdatedAt   time.Time       `json:"updated_at"    gorm:"not null;default:CURRENT_TIMESTAMP"`
}

func (Conversation) TableName() string {
	return "conversations"
}
