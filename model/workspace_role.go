package model

type WorkspaceRole struct {
	Model
	Name        string                  `json:"name"`
	Permissions []*WorkspacePermissions `json:"permissions" gorm:"many2many:workspace_role_permissions;"`
}
