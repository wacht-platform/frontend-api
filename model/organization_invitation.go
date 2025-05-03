package model

type OrganizationInvitation struct {
	Model
	OrganizationID            uint                   `json:"organization_id"`
	Email                     string                 `json:"email"`
	InitialOrganizationRoleID uint                   `json:"initial_organization_role_id"`
	InitialOrganizationRole   OrganizationRole       `json:"initial_organization_role" gorm:"foreignKey:InitialOrganizationRoleID"`
	Inviter                   OrganizationMembership `json:"inviter"`
	Workspace                 Workspace              `json:"workspace"`
	InitialWorkspaceRole      WorkspaceRole          `json:"initial_workspace_role"`
	Expired                   bool                   `json:"expired"`
}
