package model

type OrganizationDomain struct {
	Model
	OrganizationID            uint       `json:"organization_id,string" gorm:"not null"`
	DeploymentID              uint       `json:"-" gorm:"not null;index:idx_deployment_id_domain,unique"`
	Deployment                Deployment `json:"-" gorm:"foreignKey:DeploymentID"`
	Fqdn                      string     `json:"fqdn" gorm:"not null;index:idx_deployment_id_domain,unique"`
	Verified                  bool       `json:"verified" gorm:"not null"`
	VerificationDnsRecordType string     `json:"verification_dns_record_type"`
	VerificationDnsRecordName string     `json:"verification_dns_record_name"`
	VerificationDnsRecordData string     `json:"verification_dns_record_data"`
	VerificationAttempts      uint       `json:"verification_attempts" gorm:"not null;default:0"`
}
