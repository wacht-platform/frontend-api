package model

import (
	"github.com/godruoyi/go-snowflake"
)

type SignIn struct {
	Model
	SessionID uint   `json:"-" gorm:"index:idx_session_user_id,unique"`
	UserID    uint   `json:"-" gorm:"index:idx_session_user_id,unique"`
	User      *User  `json:"user,omitempty"`
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
