package model

type DeploymentWorkspaceRole struct {
	Model
	Name         string   `json:"name" gorm:"not null"`
	Permissions  []string `json:"permissions" gorm:"type:text[];not null"`
	DeploymentID uint     `json:"deployment_id" gorm:"not null;index"`
}
