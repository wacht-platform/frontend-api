package model

import "time"

type OrganizationDomain struct {
	ID                        uint64     `gorm:"primarykey"              json:"id,string"`
	CreatedAt                 time.Time  `gorm:"autoCreateTime;not null" json:"created_at"`
	UpdatedAt                 time.Time  `gorm:"autoUpdateTime;not null" json:"updated_at"`
	OrganizationID            uint64     `json:"organization_id,string" gorm:"not null"`
	DeploymentID              uint64     `json:"-" gorm:"not null;index:idx_deployment_id_domain,unique"`
	Deployment                Deployment `json:"-" gorm:"foreignKey:DeploymentID"`
	Fqdn                      string     `json:"fqdn" gorm:"not null;index:idx_deployment_id_domain,unique"`
	Verified                  bool       `json:"verified" gorm:"not null"`
	VerificationDnsRecordType string     `json:"verification_dns_record_type"`
	VerificationDnsRecordName string     `json:"verification_dns_record_name"`
	VerificationDnsRecordData string     `json:"verification_dns_record_data"`
	VerificationAttempts      uint64     `json:"verification_attempts" gorm:"not null;default:0"`
}
