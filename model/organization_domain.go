package model

type OrganizationDomain struct {
	Model
	OrganizationID            uint   `json:"organization_id,string" gorm:"not null"`
	Domain                    string `json:"domain" gorm:"not null"`
	Verified                  bool   `json:"verified" gorm:"not null"`
	VerificationDnsRecordType string `json:"verification_dns_record_type"`
	VerificationDnsRecordName string `json:"verification_dns_record_name"`
	VerificationDnsRecordData string `json:"verification_dns_record_data"`
	VerificationAttempts      uint   `json:"verification_attempts" gorm:"not null;default:0"`
}
