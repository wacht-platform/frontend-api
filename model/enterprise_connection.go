package model

import "time"

type EnterpriseConnection struct {
	ID             uint64              `gorm:"primarykey"              json:"id,string"`
	CreatedAt      time.Time           `gorm:"autoCreateTime;not null" json:"created_at"`
	UpdatedAt      time.Time           `gorm:"autoUpdateTime;not null" json:"updated_at"`
	OrganizationID uint64              `gorm:"not null"                json:"organization_id,string"`
	DeploymentID   uint64              `gorm:"not null"                json:"deployment_id,string"`
	DomainID       *uint64             `                               json:"domain_id,string"`
	Domain         *OrganizationDomain `gorm:"foreignKey:DomainID"     json:"domain,omitempty"`
	Protocol       string              `gorm:"not null"                json:"protocol"` // 'saml' or 'oidc'
	IdpEntityID    string              `                               json:"idp_entity_id"`
	IdpSSOURL      string              `                               json:"idp_sso_url"`
	IdpCertificate string              `                               json:"idp_certificate"`

	// OIDC-specific fields
	OIDCClientID     *string `gorm:"column:oidc_client_id"     json:"oidc_client_id,omitempty"`
	OIDCClientSecret *string `gorm:"column:oidc_client_secret" json:"-"` // Never expose in JSON responses
	OIDCIssuerURL    *string `gorm:"column:oidc_issuer_url"    json:"oidc_issuer_url,omitempty"`
	OIDCScopes       *string `gorm:"column:oidc_scopes"        json:"oidc_scopes,omitempty"`
}
