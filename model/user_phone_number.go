package model

import "time"

type UserPhoneNumber struct {
	Model
	UserID       uint64     `json:"-"`
	User         User       `json:"-"            gorm:"foreignKey:UserID"`
	PhoneNumber  string     `json:"phone_number" gorm:"not null"`
	CountryCode  string     `json:"country_code" gorm:"not null;default:''"`
	Verified     bool       `json:"verified"     gorm:"not null"`
	VerifiedAt   time.Time  `json:"verified_at"`
	DeploymentID uint64     `json:"-"`
	Deployment   Deployment `json:"-"            gorm:"foreignkey:DeploymentID"`
}
