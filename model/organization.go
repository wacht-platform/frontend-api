package model

import "gorm.io/datatypes"

type Organization struct {
	Model
	DeploymentID     uint                          `json:"-"               gorm:"not null;index"`
	Name             string                        `json:"name"            gorm:"not null"`
	ImageUrl         string                        `json:"image_url"       gorm:"not null"`
	Description      string                        `json:"description"`
	MemberCount      uint32                        `json:"member_count"    gorm:"not null"`
	Roles            []*DeploymentOrganizationRole `json:"roles"`
	Members          []*OrganizationMembership     `json:"members"`
	Workspaces       []*Workspace                  `json:"workspaces"`
	WorkspaceRoles   []*DeploymentWorkspaceRole    `json:"workspace_roles"`
	WorkspaceMembers []*WorkspaceMembership        `json:"workspace_members"`
	PublicMetadata   datatypes.JSONMap             `json:"public_metadata" gorm:"not null"`
	PrivateMetadata  datatypes.JSONMap             `json:"-"               gorm:"not null"`
}
