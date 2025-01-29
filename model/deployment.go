package model

import "database/sql/driver"

type DeploymentMode string

const (
	DeploymentModeProduction DeploymentMode = "production"
	DeploymentModeStaging    DeploymentMode = "staging"
)

func (m *DeploymentMode) Scan(value any) error {
	*m = DeploymentMode(value.(string))
	return nil
}

func (m *DeploymentMode) Value() (driver.Value, error) {
	return string(*m), nil
}

func (m DeploymentMode) GormDataType() string {
	return "text"
}

func (m DeploymentMode) GormDBDataType() string {
	return "text"
}

type Deployment struct {
	Model
	MaintenanceMode   bool                         `json:"maintenance_mode"`
	Host              string                       `json:"host"`
	PublishableKey    string                       `json:"publishable_key"`
	Secret            string                       `json:"-"`
	DisplaySettings   DisplaySettings              `json:"display_settings"`
	OrgSettings       OrgSettings                  `json:"org_settings"`
	AuthSettings      AuthSettings                 `json:"auth_settings"`
	SocialConnections []DeploymentSocialConnection `json:"social_connections"`
	ProjectID         uint                         `json:"project_id"`
	Project           Project                      `json:"-"`
	Mode              DeploymentMode               `json:"mode"`
	KepPair           DeploymentKeyPair            `json:"-"`
}

func (d *Deployment) IsProduction() bool {
	return d.Mode == DeploymentModeProduction
}
