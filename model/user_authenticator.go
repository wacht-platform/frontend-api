package model

type UserAuthenticator struct {
	Model
	UserID     *uint  `json:"user_id,string" gorm:"index;"`
	TotpSecret string `json:"-"`
	OtpUrl     string `json:"otp_url"`
}
