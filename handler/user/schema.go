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
