package model

type OrganizationBillingAddress struct {
	Model
	OrganizationID uint64 `json:"-" gorm:"not null;index"`
	Address        string `json:"address" gorm:"not null"`
	City           string `json:"city" gorm:"not null"`
	State          string `json:"state" gorm:"not null"`
	Country        string `json:"country" gorm:"not null"`
	PostalCode     string `json:"postal_code" gorm:"not null"`
}
