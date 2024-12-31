package model

import (
	"github.com/godruoyi/go-snowflake"
)

type SignIn struct {
	Model
	SessionID uint   `json:"session_id"`
	UserID    uint   `json:"user_id"`
	Expired   bool   `json:"expired"`
	ExpiredAt string `json:"expired_at"`
}

func NewSignIn(sessionID, userID uint) *SignIn {
	return &SignIn{
		Model: Model{
			ID: uint(snowflake.ID()),
		},
		SessionID: sessionID,
		UserID:    userID,
		Expired:   false,
	}
}
