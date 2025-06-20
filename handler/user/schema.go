package user

import "github.com/ilabs/wacht-fe/model"

type UpdateUserSchema struct {
	FirstName             string                   `form:"first_name"`
	LastName              string                   `form:"last_name"`
	Username              string                   `form:"username"`
	PrimaryEmailAddressID string                   `form:"primary_email_address_id"`
	PrimaryPhoneNumberID  string                   `form:"primary_phone_number_id"`
	SecondFactorPolicy    model.SecondFactorPolicy `form:"second_factor_policy"     validate:"oneof=none optional enforced"`
}

type AddUserEmailAddressSchema struct {
	Email string `form:"email" validate:"required,email"`
}

type AddUserPhoneNumberSchema struct {
	PhoneNumber string `form:"phone_number" validate:"required"`
}

type VerifyAuthenticatorSchema struct {
	AuthenticatorID string   `form:"authenticator_id" validate:"required"`
	Codes           []string `form:"codes"            validate:"required,min=2,max=2"`
}

type UpdatePasswordSchema struct {
	CurrentPassword string `form:"current_password" validate:"required"`
	NewPassword     string `form:"new_password"     validate:"required"`
}

type DeleteAccountSchema struct {
	Password string `form:"password" validate:"required"`
}

type RemovePasswordSchema struct {
	CurrentPassword string `form:"current_password" validate:"required"`
}
