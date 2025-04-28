package model

type SocialConnection struct {
	Model
	UserID             uint                     `json:"-"                     gorm:"not null"`
	UserEmailAddressID uint                     `json:"user_email_address_id" gorm:"not null"`
	Provider           SocialConnectionProvider `json:"provider"              gorm:"not null"`
	EmailAddress       string                   `json:"email_address"         gorm:"not null"`
	FirstName          string                   `json:"first_name"            gorm:"not null"`
	LastName           string                   `json:"last_name"             gorm:"not null"`
	AccessToken        string                   `json:"-"`
	RefreshToken       string                   `json:"-"`
}
