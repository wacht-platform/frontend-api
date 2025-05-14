package model

import "time"

type UserPhoneNumber struct {
	Model
	UserID                uint64    `json:"-"`
	PhoneNumber           string    `json:"phone_number"              gorm:"not null"`
	CanUseForSecondFactor bool      `json:"can_use_for_second_factor" gorm:"not null"`
	Verified              bool      `json:"verified"                  gorm:"not null"`
	VerifiedAt            time.Time `json:"verified_at"`
}
