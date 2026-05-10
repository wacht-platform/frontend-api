package model

import (
	"time"

	"gorm.io/datatypes"
)

type EnterpriseConnection struct {
	ID               uint64              `gorm:"primarykey"                            json:"id,string"`
	CreatedAt        time.Time           `gorm:"autoCreateTime;not null"               json:"created_at"`
	UpdatedAt        time.Time           `gorm:"autoUpdateTime;not null"               json:"updated_at"`
	OrganizationID   uint64              `gorm:"not null"                              json:"organization_id,string"`
	DeploymentID     uint64              `gorm:"not null"                              json:"deployment_id,string"`
	DomainID         uint64              `gorm:"not null"                              json:"domain_id,string"`
	Domain           *OrganizationDomain `gorm:"foreignKey:DomainID"                   json:"domain,omitempty"`
	Protocol         string              `gorm:"not null"                              json:"protocol"`
	IdpEntityID      string              `                                             json:"idp_entity_id"`
	IdpSSOURL        string              `                                             json:"idp_sso_url"`
	IdpCertificate   string              `                                             json:"idp_certificate"`
	OIDCClientID     *string             `gorm:"column:oidc_client_id"                 json:"oidc_client_id,omitempty"`
	OIDCClientSecret *string             `gorm:"column:oidc_client_secret"             json:"-"`
	OIDCIssuerURL    *string             `gorm:"column:oidc_issuer_url"                json:"oidc_issuer_url,omitempty"`
	OIDCScopes       *string             `gorm:"column:oidc_scopes"                    json:"oidc_scopes,omitempty"`
	JitEnabled       bool                `gorm:"column:jit_enabled;default:true"       json:"jit_enabled"`
	AttributeMapping datatypes.JSONMap   `gorm:"column:attribute_mapping;default:'{}'" json:"attribute_mapping,omitempty"`
}
