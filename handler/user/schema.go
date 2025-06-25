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

type OrganizationMembershipQueryResult struct {
	model.OrganizationMembership
	OrganizationName        string `gorm:"column:organization_name"`
	OrganizationImageUrl    string `gorm:"column:organization_image_url"`
	OrganizationDescription string `gorm:"column:organization_description"`
	OrganizationMemberCount uint32 `gorm:"column:organization_member_count"`
	RolesJSON               string `gorm:"column:roles_json"`
}

type WorkspaceMembershipQueryResult struct {
	model.WorkspaceMembership
	WorkspaceName        string `gorm:"column:workspace_name"`
	WorkspaceImageUrl    string `gorm:"column:workspace_image_url"`
	WorkspaceDescription string `gorm:"column:workspace_description"`
	WorkspaceMemberCount uint64 `gorm:"column:workspace_member_count"`
	OrganizationName     string `gorm:"column:organization_name"`
	OrganizationImageUrl string `gorm:"column:organization_image_url"`
	RolesJSON            string `gorm:"column:roles_json"`
}
