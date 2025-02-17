package model

import (
	"github.com/godruoyi/go-snowflake"
)

type Signin struct {
	Model
	SessionID    uint   `json:"-"              gorm:"index:idx_session_user_id,unique"`
	UserID       uint   `json:"-"              gorm:"index:idx_session_user_id,unique"`
	User         *User  `json:"user,omitempty"`
	ExpiresAt    string `json:"expires_at"`
	LastActiveAt string `json:"last_active_at"`
	IpAddress    string `json:"ip_address"`
	Browser      string `json:"browser"`
	Device       string `json:"device"`
	City         string `json:"city"`
	Region       string `json:"region"`
	RegionCode   string `json:"region_code"`
	Country      string `json:"country"`
	CountryCode  string `json:"country_code"`
}

func NewSignIn(sessionID, userID uint) *Signin {
	return &Signin{
		Model: Model{
			ID: uint(snowflake.ID()),
		},
		SessionID: sessionID,
		UserID:    userID,
	}
}
