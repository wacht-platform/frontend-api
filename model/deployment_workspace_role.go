package model

type DeploymentWorkspaceRole struct {
	Model
	OrganizationID uint     `json:"organization_id" gorm:"index"`
	Name           string   `json:"name"          gorm:"not null"`
	Permissions    []string `json:"permissions"   gorm:"type:text[];not null"`
	DeploymentID   uint     `json:"deployment_id" gorm:"not null;index"`
	WorkspaceID    uint     `json:"workspace_id"  gorm:"index"`
}
