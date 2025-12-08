package model

import "time"

// SCIMToken stores bearer tokens for SCIM authentication
// Each enterprise connection can have one SCIM token
type SCIMToken struct {
	ID                     uint64     `gorm:"primarykey"              json:"id,string"`
	EnterpriseConnectionID uint64     `gorm:"not null;unique"         json:"enterprise_connection_id,string"`
	DeploymentID           uint64     `gorm:"not null"                json:"-"`
	OrganizationID         uint64     `gorm:"not null"                json:"organization_id,string"`
	TokenHash              string     `gorm:"not null"                json:"-"`
	TokenPrefix            string     `gorm:"not null"                json:"token_prefix"`
	Enabled                bool       `gorm:"not null;default:true"   json:"enabled"`
	LastUsedAt             *time.Time `                               json:"last_used_at"`
	CreatedAt              time.Time  `gorm:"autoCreateTime;not null" json:"created_at"`
	UpdatedAt              time.Time  `gorm:"autoUpdateTime;not null" json:"updated_at"`
}
