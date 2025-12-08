package model

import "time"

// SCIMExternalID maps external IdP user IDs to Wacht user IDs
// Used for deduplication during SCIM sync operations
type SCIMExternalID struct {
	ID                     uint64    `gorm:"primarykey"              json:"id,string"`
	EnterpriseConnectionID uint64    `gorm:"not null"                json:"enterprise_connection_id,string"`
	DeploymentID           uint64    `gorm:"not null"                json:"-"`
	ExternalID             string    `gorm:"not null"                json:"external_id"`
	UserID                 uint64    `gorm:"not null"                json:"user_id,string"`
	User                   *User     `gorm:"foreignKey:UserID"       json:"user,omitempty"`
	CreatedAt              time.Time `gorm:"autoCreateTime;not null" json:"created_at"`
	UpdatedAt              time.Time `gorm:"autoUpdateTime;not null" json:"updated_at"`
}
