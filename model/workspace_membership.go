package model

type WorkspaceMembershipRoleAssoc struct {
	WorkspaceMembershipID uint `gorm:"primaryKey"`
	WorkspaceRoleID       uint `gorm:"primaryKey"`
	WorkspaceID           uint `gorm:"not null;index"`
	OrganizationID        uint `gorm:"not null;index"`
}

func (WorkspaceMembershipRoleAssoc) TableName() string {
	return "workspace_membership_roles"
}

type WorkspaceMembership struct {
	Model
	WorkspaceID              uint                           `json:"-"    gorm:"not null"`
	Workspace                Workspace                      `json:"workspace"       gorm:"foreignKey:WorkspaceID"`
	OrganizationID           uint                           `json:"organization_id,string" gorm:"not null;index"`
	Organization             Organization                   `json:"organization" gorm:"foreignKey:OrganizationID"`
	OrganizationMembershipID uint                           `json:"organization_membership_id,string" gorm:"not null;index"`
	OrganizationMembership   OrganizationMembership         `json:"organization_membership" gorm:"foreignKey:OrganizationMembershipID"`
	UserID                   uint                           `json:"user_id,string"         gorm:"not null;index"`
	User                     PublicUserData                 `json:"public_user_data" gorm:"foreignKey:UserID"`
	Role                     []*WorkspaceRole               `json:"role" gorm:"many2many:workspace_membership_roles;joinForeignKey:WorkspaceMembershipID;JoinReferences:WorkspaceRoleID;References:ID;foreignKey:ID"`
	RoleAssociations         []WorkspaceMembershipRoleAssoc `json:"-" gorm:"foreignKey:WorkspaceMembershipID;references:ID"`
}
