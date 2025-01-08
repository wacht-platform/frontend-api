package model

type WorkspaceRole struct {
	Model
	Name        string                      `json:"name"`
	Permissions []*WorkspaceRolePermissions `json:"permissions"`
}
