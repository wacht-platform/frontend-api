package model

import "time"

type UserPhoneNumber struct {
	Model
	UserID      uint      `json:"-"`
	PhoneNumber string    `json:"phone_number"`
	Verified    bool      `json:"verified"`
	VerifiedAt  time.Time `json:"verified_at"`
}
