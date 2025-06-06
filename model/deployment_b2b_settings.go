package model

import "github.com/lib/pq"

type DeploymentB2bSettings struct {
	Model
	DeploymentID                  uint64           `json:"deployment_id"                     gorm:"not null;index"`
	OrganizationsEnabled          bool             `json:"organizations_enabled"             gorm:"not null"`
	WorkspacesEnabled             bool             `json:"workspaces_enabled"                gorm:"not null"`
	IpAllowlistPerOrgEnabled      bool             `json:"ip_allowlist_per_org_enabled"      gorm:"not null"`
	MaxAllowedOrgMembers          uint64           `json:"max_allowed_org_members"           gorm:"not null"`
	MaxAllowedWorkspaceMembers    uint64           `json:"max_allowed_workspace_members"     gorm:"not null"`
	AllowOrgDeletion              bool             `json:"allow_org_deletion"                gorm:"not null"`
	AllowWorkspaceDeletion        bool             `json:"allow_workspace_deletion"          gorm:"not null"`
	CustomOrgRoleEnabled          bool             `json:"custom_org_role_enabled"           gorm:"not null"`
	CustomWorkspaceRoleEnabled    bool             `json:"custom_workspace_role_enabled"     gorm:"not null"`
	DefaultWorkspaceCreatorRoleID uint64           `json:"default_workspace_creator_role_id" gorm:"not null"`
	DefaultWorkspaceMemberRoleID  uint64           `json:"default_workspace_member_role_id"  gorm:"not null"`
	DefaultOrgCreatorRoleID       uint64           `json:"default_org_creator_role_id"       gorm:"not null"`
	DefaultOrgMemberRoleID        uint64           `json:"default_org_member_role_id"        gorm:"not null"`
	LimitOrgCreationPerUser       bool             `json:"limit_org_creation_per_user"       gorm:"not null"`
	LimitWorkspaceCreationPerOrg  bool             `json:"limit_workspace_creation_per_org"  gorm:"not null"`
	OrgCreationPerUserCount       uint16         `json:"org_creation_per_user_count"       gorm:"not null"`
	WorkspacesPerOrgCount         uint16         `json:"workspaces_per_org_count"          gorm:"not null"`
	AllowUsersToCreateOrgs        bool             `json:"allow_users_to_create_orgs"        gorm:"not null"`
	MaxOrgsPerUser                uint16         `json:"max_orgs_per_user"                 gorm:"not null"`
	DefaultWorkspaceCreatorRole   WorkspaceRole    `json:"default_workspace_creator_role"    gorm:"foreignKey:DefaultWorkspaceCreatorRoleID"`
	DefaultWorkspaceMemberRole    WorkspaceRole    `json:"default_workspace_member_role"     gorm:"foreignKey:DefaultWorkspaceMemberRoleID"`
	DefaultOrgCreatorRole         OrganizationRole `json:"default_org_creator_role"          gorm:"foreignKey:DefaultOrgCreatorRoleID"`
	DefaultOrgMemberRole          OrganizationRole `json:"default_org_member_role"           gorm:"foreignKey:DefaultOrgMemberRoleID"`
	WorkspacePermissions          pq.StringArray   `json:"workspace_permissions"             gorm:"type:text[]"`
	OrganizationPermissions       pq.StringArray   `json:"organization_permissions"          gorm:"type:text[]"`
}
