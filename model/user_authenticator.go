package model

type UserAuthenticator struct {
	Model
	UserID     *uint64 `json:"user_id,string" gorm:"index;"`
	TotpSecret string  `json:"-"              gorm:"not null"`
	OtpUrl     string  `json:"otp_url"`
}
