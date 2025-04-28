package model

type DeploymentOrganizationRole struct {
	Model
	OrganizationID uint     `json:"organization_id" gorm:"index"`
	Name           string   `json:"name"          gorm:"not null"`
	Permissions    []string `json:"permissions"   gorm:"type:text[];not null"`
	DeploymentID   uint     `json:"deployment_id" gorm:"not null;index"`
}
