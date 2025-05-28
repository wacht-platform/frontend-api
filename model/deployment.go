package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"gorm.io/gorm"
)

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

type DnsRecord struct {
	Name                    string    `json:"name"`
	RecordType              string    `json:"record_type"`
	Value                   string    `json:"value"`
	Verified                bool      `json:"verified"`
	VerificationAttemptedAt time.Time `json:"verification_attempted_at"`
	LastVerifiedAt          time.Time `json:"last_verified_at"`
}

type DomainVerificationRecords struct {
	CloudflareVerification     []DnsRecord `json:"cloudflare_verification"`
	CustomHostnameVerification []DnsRecord `json:"custom_hostname_verification"`
}

func (d *DomainVerificationRecords) Scan(value any) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("invalid type for DomainVerificationRecords")
	}
	return json.Unmarshal(bytes, d)
}

func (d *DomainVerificationRecords) Value() (driver.Value, error) {
	return json.Marshal(d)
}

type EmailVerificationRecords struct {
	SesVerification      []DnsRecord `json:"ses_verification"`
	MailFromVerification []DnsRecord `json:"mail_from_verification"`
	DkimRecords          []DnsRecord `json:"dkim_records"`
}

func (e *EmailVerificationRecords) Scan(value any) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("invalid type for EmailVerificationRecords")
	}
	return json.Unmarshal(bytes, e)
}

func (e *EmailVerificationRecords) Value() (driver.Value, error) {
	return json.Marshal(e)
}

type Deployment struct {
	Model
	MaintenanceMode           bool                         `json:"maintenance_mode"   gorm:"not null"`
	BackendHost               string                       `json:"backend_host"       gorm:"not null"`
	FrontendHost              string                       `json:"frontend_host"      gorm:"not null"`
	MailFromHost              string                       `json:"mail_from_host"     gorm:"not null"`
	PublishableKey            string                       `json:"publishable_key"    gorm:"not null"`
	UISettings                DeploymentUISettings         `json:"ui_settings"`
	B2BSettings               DeploymentB2bSettings        `json:"b2b_settings"`
	AuthSettings              DeploymentAuthSettings       `json:"auth_settings"`
	Restrictions              DeploymentRestrictions       `json:"restrictions"`
	SocialConnections         []DeploymentSocialConnection `json:"social_connections"`
	JwtTemplates              []DeploymentJwtTemplate      `json:"-"`
	WorkspaceRoles            []WorkspaceRole              `json:"-"`
	OrgRoles                  []OrganizationRole           `json:"-"`
	EmailTemplates            *DeploymentEmailTemplate     `json:"email_templates"`
	SmsTemplates              *DeploymentSmsTemplate       `json:"sms_templates"`
	ProjectID                 uint64                       `json:"project_id"         gorm:"not null"`
	Project                   Project                      `json:"-"`
	Mode                      DeploymentMode               `json:"mode"               gorm:"not null"`
	KepPair                   DeploymentKeyPair            `json:"-"`
	DomainVerificationRecords *DomainVerificationRecords   `json:"domain_verification_records"`
	EmailVerificationRecords  *EmailVerificationRecords    `json:"email_verification_records"`
}

func (d *Deployment) IsProduction() bool {
	return d.Mode == DeploymentModeProduction
}

func (d *Deployment) LoadKepPair(db *gorm.DB) error {
	keypair := new(DeploymentKeyPair)
	err := db.Where("deployment_id = ?", d.ID).First(&keypair).Error

	if err != nil {
		return err
	}

	d.KepPair = *keypair
	return nil
}
