package model

type SocialConnection struct {
	Model
	UserID             uint
	UserEmailAddressID uint
	Provider           SocialConnectionProvider
	EmailAdress        string
	AcessToken         string
	RefreshToken       string
}
