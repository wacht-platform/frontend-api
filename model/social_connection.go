package model

type SocialConnection struct {
	Model
	UserID             uint                     `json:"-"`
	UserEmailAddressID uint                     `json:"user_email_address_id"`
	Provider           SocialConnectionProvider `json:"provider"`
	EmailAddress       string                   `json:"email_address"`
	FirstName          string                   `json:"first_name"`
	LastName           string                   `json:"last_name"`
	AccessToken        string                   `json:"-"`
	RefreshToken       string                   `json:"-"`
}
