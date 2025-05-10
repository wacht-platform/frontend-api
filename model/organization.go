package model

import (
	"github.com/lib/pq"
	"gorm.io/datatypes"
)

type Organization struct {
	Model
	DeploymentID            uint                          `json:"-"               gorm:"not null;index"`
	Name                    string                        `json:"name"            gorm:"not null"`
	ImageUrl                string                        `json:"image_url"       gorm:"not null"`
	Description             string                        `json:"description"`
	MemberCount             uint32                        `json:"member_count"    gorm:"not null"`
	Roles                   []*OrganizationRole           `json:"roles"`
	Members                 []*OrganizationMembership     `json:"members"`
	Workspaces              []*Workspace                  `json:"workspaces"`
	WorkspaceRoles          []*WorkspaceRole              `json:"workspace_roles"`
	WorkspaceMembers        []*WorkspaceMembership        `json:"workspace_members"`
	Domains                 []*OrganizationDomain         `json:"domains"`
	BillingAddresses        []*OrganizationBillingAddress `json:"billing_addresses"`
	Invitations             []*OrganizationInvitation     `json:"invitations"`
	EnforceMFASetup         bool                          `json:"enforce_2fa" gorm:"not null;default:false"`
	EnableIPRestriction     bool                          `json:"enable_ip_restriction" gorm:"not null;default:false"`
	WhitelistedIPs          pq.StringArray                `json:"whitelisted_ips" gorm:"type:text[]"`
	AutoAssignedWorkspaceID *uint                         `json:"auto_assigned_workspace_id"`
	AutoAssignedWorkspace   *Workspace                    `json:"auto_assigned_workspace" gorm:"foreignKey:AutoAssignedWorkspaceID"`
	PublicMetadata          datatypes.JSONMap             `json:"public_metadata" gorm:"not null"`
	PrivateMetadata         datatypes.JSONMap             `json:"-"               gorm:"not null"`
}
