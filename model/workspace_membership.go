package model

type WorkspaceMembershipRoleAssoc struct {
	WorkspaceMembershipID uint64 `gorm:"primaryKey"`
	WorkspaceRoleID       uint64 `gorm:"primaryKey"`
	WorkspaceID           uint64 `gorm:"not null;index"`
	OrganizationID        uint64 `gorm:"not null;index"`
}

func (WorkspaceMembershipRoleAssoc) TableName() string {
	return "workspace_membership_roles"
}

type WorkspaceMembership struct {
	Model
	WorkspaceID              uint64                         `json:"-"    gorm:"not null"`
	Workspace                Workspace                      `json:"workspace"       gorm:"foreignKey:WorkspaceID"`
	OrganizationID           uint64                         `json:"organization_id,string" gorm:"not null;index"`
	Organization             Organization                   `json:"organization" gorm:"foreignKey:OrganizationID"`
	OrganizationMembershipID uint64                         `json:"organization_membership_id,string" gorm:"not null;index"`
	OrganizationMembership   OrganizationMembership         `json:"organization_membership" gorm:"foreignKey:OrganizationMembershipID"`
	UserID                   uint64                         `json:"user_id,string"         gorm:"not null;index"`
	User                     PublicUserData                 `json:"public_user_data" gorm:"foreignKey:UserID"`
	Roles                    []*WorkspaceRole               `json:"roles" gorm:"many2many:workspace_membership_roles;joinForeignKey:WorkspaceMembershipID;JoinReferences:WorkspaceRoleID;References:ID;foreignKey:ID"`
	RoleAssociations         []WorkspaceMembershipRoleAssoc `json:"-" gorm:"foreignKey:WorkspaceMembershipID;references:ID"`
}
