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
	MaintenanceMode   bool                         `json:"maintenance_mode" gorm:"not null"`
	BackendHost       string                       `json:"backend_host" gorm:"not null"`
	FrontendHost      string                       `json:"frontend_host" gorm:"not null"`
	MailFromHost      string                       `json:"mail_from_host" gorm:"not null"`
	PublishableKey    string                       `json:"publishable_key" gorm:"not null"`
	UISettings        DeploymentUISettings         `json:"ui_settings"`
	OrgSettings       DeploymentB2bSettings        `json:"org_settings"`
	AuthSettings      DeploymentAuthSettings       `json:"auth_settings"`
	Restrictions      DeploymentRestrictions       `json:"restrictions"`
	SocialConnections []DeploymentSocialConnection `json:"social_connections"`
	JwtTemplates      []DeploymentJwtTemplate      `json:"-"`
	WorkspaceRoles    []DeploymentWorkspaceRole    `json:"-"`
	OrgRoles          []DeploymentOrganizationRole `json:"-"`
	EmailTemplates    *DeploymentEmailTemplate     `json:"email_templates"`
	SmsTemplates      *DeploymentSmsTemplate       `json:"sms_templates"`
	ProjectID         uint                         `json:"project_id" gorm:"not null"`
	Project           Project                      `json:"-"`
	Mode              DeploymentMode               `json:"mode" gorm:"not null"`
	KepPair           DeploymentKeyPair            `json:"-"`
}

func (d *Deployment) IsProduction() bool {
	return d.Mode == DeploymentModeProduction
}
