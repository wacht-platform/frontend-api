package model

type SocialConnection struct {
	Model
	UserID             uint
	UserEmailAddressID uint
	Provider           SSOProvider
	EmailAdress        string
	AcessToken         string
	RefreshToken       string
}
