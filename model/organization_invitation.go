package model

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

type OrganizationInvitation struct {
	Model
	OrganizationID            uint64                 `json:"organization_id,string"`
	Email                     string                 `json:"email"`
	Token                     string                 `json:"-"                                             gorm:"unique;not null"`
	InitialOrganizationRoleID *uint64                `json:"initial_organization_role_id,string,omitempty"`
	InitialOrganizationRole   OrganizationRole       `json:"initial_organization_role"                     gorm:"foreignKey:InitialOrganizationRoleID"`
	InviterID                 uint64                 `json:"inviter_id,string"`
	Inviter                   OrganizationMembership `json:"inviter"                                       gorm:"foreignKey:InviterID"`
	WorkspaceID               *uint64                `json:"workspace_id,string,omitempty"`
	Workspace                 Workspace              `json:"workspace"                                     gorm:"foreignKey:WorkspaceID"`
	InitialWorkspaceRoleID    *uint64                `json:"initial_workspace_role_id,string,omitempty"`
	InitialWorkspaceRole      WorkspaceRole          `json:"initial_workspace_role"                        gorm:"foreignKey:InitialWorkspaceRoleID"`
	Expiry                    time.Time              `json:"expiry"                                        gorm:"default:CURRENT_TIMESTAMP + INTERVAL '10 DAY'"`
}

func (o *OrganizationInvitation) BeforeSave(tx *gorm.DB) error {
	o.Email = strings.ToLower(strings.TrimSpace(o.Email))
	return nil
}
