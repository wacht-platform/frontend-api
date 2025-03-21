package user

import "github.com/ilabs/wacht-fe/model"

type UpdateUserSchema struct {
	FirstName             string                   `json:"first_name"`
	LastName              string                   `json:"last_name"`
	Username              string                   `json:"username"`
	PrimaryEmailAddressID string                   `json:"primary_email_address_id"`
	PrimaryPhoneNumberID  string                   `json:"primary_phone_number_id"`
	SecondFactorPolicy    model.SecondFactorPolicy `json:"second_factor_policy"     validate:"oneof=none optional enforced"`
}

type AddUserEmailAddressSchema struct {
	Email string `json:"email" validate:"required,email"`
}

type AddUserPhoneNumberSchema struct {
	PhoneNumber string `json:"phone_number" validate:"required"`
}

type VerifyAuthenticatorSchema struct {
	AuthenticatorID string   `json:"authenticator_id" validate:"required"`
	Codes           []string `json:"codes"            validate:"required,min=2,max=2"`
}
