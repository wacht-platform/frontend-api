package model

import "time"

type UserPhoneNumber struct {
	Model
	UserID                uint      `json:"-"`
	PhoneNumber           string    `json:"phone_number"`
	CanUseForSecondFactor bool      `json:"can_use_for_second_factor"`
	Verified              bool      `json:"verified"`
	VerifiedAt            time.Time `json:"verified_at"`
}
