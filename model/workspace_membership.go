package model

type WorkspaceMembership struct {
	Model
	WorkspaceID uint             `json:"workspace_id"`
	UserID      uint             `json:"user_id"`
	Role        []*WorkspaceRole `json:"role" gorm:"many2many:workspace_membership_roles;"`
}
