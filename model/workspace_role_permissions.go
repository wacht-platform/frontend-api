package model

type WorkspacePermissions struct {
	Model
	WorkspaceRoleID uint   `json:"workspace_role_id"`
	Permission      string `json:"permission"`
}
