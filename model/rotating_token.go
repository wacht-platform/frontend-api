package model

import "time"

type RotatingToken struct {
	Model
	SessionID  uint
	ValidUntil time.Time
}

func (r *RotatingToken) IsValid() bool {
	return r.ValidUntil.After(time.Now())
}

func NewRotatingToken(sessionID uint, validUntil time.Time) *RotatingToken {
	return &RotatingToken{
		SessionID:  sessionID,
		ValidUntil: validUntil,
	}
}
