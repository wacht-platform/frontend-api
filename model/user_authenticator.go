package model

type UserAuthenticator struct {
	Model
	UserID     *uint64 `json:"user_id,string" gorm:"index;"`
	TotpSecret string  `json:"-"              gorm:"not null"`
	// Read-only so AutoMigrate keeps the column but the seed-bearing URL is never persisted.
	OtpUrl     *string `json:"-"              gorm:"->"`
}
