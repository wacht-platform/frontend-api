package model

type WorkspaceMembership struct {
	Model
	WorkspaceID              uint                       `json:"-"    gorm:"not null"`
	Workspace                Workspace                  `json:"workspace"       gorm:"foreignKey:WorkspaceID"`
	OrganizationID           uint                       `json:"organization_id" gorm:"not null;index"`
	OrganizationMembershipID uint                       `json:"organization_membership_id" gorm:"not null;index"`
	UserID                   uint                       `json:"user_id"         gorm:"not null;index"`
	Role                     []*WorkspaceRole `json:"role"            gorm:"many2many:workspace_membership_roles;"`
}
