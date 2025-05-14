package model

import (
	"time"

	"github.com/godruoyi/go-snowflake"
)

type RotatingToken struct {
	Model
	SessionID  uint64    `json:"session_id"  gorm:"not null"`
	ValidUntil time.Time `json:"valid_until" gorm:"not null"`
}

func (r *RotatingToken) IsValid() bool {
	return r.ValidUntil.After(
		time.Now(),
	)
}

func NewRotatingToken(
	sessionID uint64,
	validUntil time.Time,
) *RotatingToken {
	return &RotatingToken{
		Model: Model{
			ID: snowflake.ID(),
		},
		SessionID:  sessionID,
		ValidUntil: validUntil,
	}
}
