package model

import "time"

type EnterpriseConnection struct {
	ID             uint64              `gorm:"primarykey"              json:"id,string"`
	CreatedAt      time.Time           `gorm:"autoCreateTime;not null" json:"created_at"`
	UpdatedAt      time.Time           `gorm:"autoUpdateTime;not null" json:"updated_at"`
	OrganizationID uint64              `json:"organization_id,string" gorm:"not null"`
	DeploymentID   uint64              `json:"deployment_id,string" gorm:"not null"`
	DomainID       *uint64             `json:"domain_id,string"`
	Domain         *OrganizationDomain `json:"domain,omitempty" gorm:"foreignKey:DomainID"`
	Protocol       string              `json:"protocol" gorm:"not null"` // 'saml' or 'oidc'
	IdpEntityID    string              `json:"idp_entity_id"`
	IdpSSOURL      string              `json:"idp_sso_url"`
	IdpCertificate string              `json:"idp_certificate"`

	// OIDC-specific fields
	OIDCClientID     *string `json:"oidc_client_id,omitempty"`
	OIDCClientSecret *string `json:"-"` // Never expose in JSON responses
	OIDCIssuerURL    *string `json:"oidc_issuer_url,omitempty"`
	OIDCScopes       *string `json:"oidc_scopes,omitempty"`
}
