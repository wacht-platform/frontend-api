package model

import (
	"time"

	"gorm.io/datatypes"
)

type SearchUser struct {
	UserID            uint64         `gorm:"primaryKey;column:user_id" json:"user_id"`
	DeploymentID      uint64         `gorm:"column:deployment_id;not null" json:"deployment_id"`
	FirstName         string         `gorm:"column:first_name" json:"first_name"`
	LastName          string         `gorm:"column:last_name" json:"last_name"`
	Username          string         `gorm:"column:username" json:"username"`
	PrimaryEmail      string         `gorm:"column:primary_email" json:"primary_email"`
	AllEmails         datatypes.JSON `gorm:"column:all_emails;type:jsonb" json:"all_emails"`
	AllPhoneNumbers   datatypes.JSON `gorm:"column:all_phone_numbers;type:jsonb" json:"all_phone_numbers"`
	OrganizationIDs   datatypes.JSON `gorm:"column:organization_ids;type:jsonb" json:"organization_ids"`
	WorkspaceIDs      datatypes.JSON `gorm:"column:workspace_ids;type:jsonb" json:"workspace_ids"`
	OrganizationRoles datatypes.JSON `gorm:"column:organization_roles;type:jsonb" json:"organization_roles"`
	WorkspaceRoles    datatypes.JSON `gorm:"column:workspace_roles;type:jsonb" json:"workspace_roles"`
	ProfilePictureURL string         `gorm:"column:profile_picture_url" json:"profile_picture_url"`

	CreatedAt time.Time `gorm:"column:created_at" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at" json:"updated_at"`
}

func (SearchUser) TableName() string {
	return "search_users"
}

type SearchUserSyncPayload struct {
	UserID            uint64
	DeploymentID      uint64
	FirstName         string
	LastName          string
	Username          string
	PrimaryEmail      string
	AllEmails         []string
	AllPhoneNumbers   []string
	OrganizationIDs   []uint64
	WorkspaceIDs      []uint64
	OrganizationRoles []uint64
	WorkspaceRoles    []uint64
	ProfilePicture    string
}
