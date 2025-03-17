package model

import (
	"time"

	"github.com/godruoyi/go-snowflake"
)

type RotatingToken struct {
	Model
	SessionID  uint
	ValidUntil time.Time
}

func (r *RotatingToken) IsValid() bool {
	return r.ValidUntil.After(time.Now())
}

func NewRotatingToken(
	sessionID uint,
	validUntil time.Time,
) *RotatingToken {
	return &RotatingToken{
		Model: Model{
			ID: uint(snowflake.ID()),
		},
		SessionID:  sessionID,
		ValidUntil: validUntil,
	}
}
