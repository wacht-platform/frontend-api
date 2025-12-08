package model

import "time"

type OrganizationDomain struct {
	ID                        uint64     `gorm:"primarykey"                                     json:"id,string"`
	CreatedAt                 time.Time  `gorm:"autoCreateTime;not null"                        json:"created_at"`
	UpdatedAt                 time.Time  `gorm:"autoUpdateTime;not null"                        json:"updated_at"`
	OrganizationID            uint64     `gorm:"not null"                                       json:"organization_id,string"`
	DeploymentID              uint64     `gorm:"not null;index:idx_deployment_id_domain,unique" json:"-"`
	Deployment                Deployment `gorm:"foreignKey:DeploymentID"                        json:"-"`
	Fqdn                      string     `gorm:"not null;index:idx_deployment_id_domain,unique" json:"fqdn"`
	Verified                  bool       `gorm:"not null"                                       json:"verified"`
	VerificationDnsRecordType string     `                                                      json:"verification_dns_record_type"`
	VerificationDnsRecordName string     `                                                      json:"verification_dns_record_name"`
	VerificationDnsRecordData string     `                                                      json:"verification_dns_record_data"`
	VerificationAttempts      uint64     `gorm:"not null;default:0"                             json:"verification_attempts"`
}
