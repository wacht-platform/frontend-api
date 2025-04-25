package model

type WorkspaceMembership struct {
	Model
	WorkspaceID uint                       `json:"workspace_id" gorm:"not null"`
	UserID      uint                       `json:"user_id" gorm:"not null"`
	Role        []*DeploymentWorkspaceRole `json:"role"         gorm:"many2many:workspace_membership_roles;"`
}
