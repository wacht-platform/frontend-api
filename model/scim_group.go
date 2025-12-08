package model

import "time"

// SCIMGroup stores groups synced from IdP via SCIM
// Groups can be mapped to organization roles for automatic permission assignment
type SCIMGroup struct {
	ID                     uint64            `gorm:"primarykey"              json:"id,string"`
	EnterpriseConnectionID uint64            `gorm:"not null"                json:"enterprise_connection_id,string"`
	DeploymentID           uint64            `gorm:"not null"                json:"-"`
	OrganizationID         uint64            `gorm:"not null"                json:"organization_id,string"`
	ExternalID             string            `gorm:"not null"                json:"external_id"`
	DisplayName            string            `gorm:"not null"                json:"display_name"`
	OrganizationRoleID     *uint64           `                               json:"organization_role_id,string,omitempty"`
	OrganizationRole       *OrganizationRole `gorm:"foreignKey:OrganizationRoleID" json:"organization_role,omitempty"`
	Members                []SCIMGroupMember `gorm:"foreignKey:SCIMGroupID"  json:"members,omitempty"`
	CreatedAt              time.Time         `gorm:"autoCreateTime;not null" json:"created_at"`
	UpdatedAt              time.Time         `gorm:"autoUpdateTime;not null" json:"updated_at"`
}

// SCIMGroupMember tracks membership of users in SCIM groups
type SCIMGroupMember struct {
	SCIMGroupID uint64    `gorm:"primaryKey"              json:"scim_group_id,string"`
	UserID      uint64    `gorm:"primaryKey"              json:"user_id,string"`
	User        *User     `gorm:"foreignKey:UserID"       json:"user,omitempty"`
	CreatedAt   time.Time `gorm:"autoCreateTime;not null" json:"created_at"`
}
