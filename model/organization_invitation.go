package model

import "time"

type OrganizationInvitation struct {
	Model
	OrganizationID            uint64                 `json:"organization_id"`
	Email                     string                 `json:"email"`
	InitialOrganizationRoleID *uint64                `json:"initial_organization_role_id"`
	InitialOrganizationRole   OrganizationRole       `json:"initial_organization_role" gorm:"foreignKey:InitialOrganizationRoleID"`
	InviterID                 uint64                 `json:"inviter_id"`
	Inviter                   OrganizationMembership `json:"inviter" gorm:"foreignKey:InviterID"`
	WorkspaceID               *uint64                `json:"workspace_id"`
	Workspace                 Workspace              `json:"workspace" gorm:"foreignKey:WorkspaceID"`
	InitialWorkspaceRoleID    *uint64                `json:"initial_workspace_role_id"`
	InitialWorkspaceRole      WorkspaceRole          `json:"initial_workspace_role" gorm:"foreignKey:InitialWorkspaceRoleID"`
	Expiry                    time.Time              `json:"expiry" gorm:"default:CURRENT_TIMESTAMP + INTERVAL '10 DAY'"`
}
