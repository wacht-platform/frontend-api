package model

import "github.com/lib/pq"

type WorkspaceRole struct {
	Model
	OrganizationID uint64         `json:"organization_id,string" gorm:"index"`
	Name           string         `json:"name"          gorm:"not null"`
	Permissions    pq.StringArray `json:"permissions"   gorm:"type:text[];not null"`
	DeploymentID   uint64         `json:"deployment_id,string" gorm:"not null;index"`
	WorkspaceID    uint64         `json:"workspace_id,string"  gorm:"index"`
}
