package model

type OrganizationInvitation struct {
	Model
	OrganizationID            uint                   `json:"organization_id"`
	Email                     string                 `json:"email"`
	InitialOrganizationRoleID *uint                  `json:"initial_organization_role_id"`
	InitialOrganizationRole   OrganizationRole       `json:"initial_organization_role" gorm:"foreignKey:InitialOrganizationRoleID"`
	InviterID                 uint                   `json:"inviter_id"`
	Inviter                   OrganizationMembership `json:"inviter" gorm:"foreignKey:InviterID"`
	WorkspaceID               *uint                  `json:"workspace_id"`
	Workspace                 Workspace              `json:"workspace" gorm:"foreignKey:WorkspaceID"`
	InitialWorkspaceRoleID    *uint                  `json:"initial_workspace_role_id"`
	InitialWorkspaceRole      WorkspaceRole          `json:"initial_workspace_role" gorm:"foreignKey:InitialWorkspaceRoleID"`
	Expired                   bool                   `json:"expired"`
}
