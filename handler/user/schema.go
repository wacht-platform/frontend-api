package user

import (
	"time"

	"github.com/ilabs/wacht-fe/model"
)

type UpdateUserSchema struct {
	FirstName             string                   `form:"first_name"`
	LastName              string                   `form:"last_name"`
	Username              string                   `form:"username"`
	PrimaryEmailAddressID string                   `form:"primary_email_address_id"`
	PrimaryPhoneNumberID  string                   `form:"primary_phone_number_id"`
	SecondFactorPolicy    model.SecondFactorPolicy `form:"second_factor_policy"     validate:"omitempty,oneof=none enforced"`
	RemoveProfilePicture  bool                     `form:"remove_profile_picture"`
}

type AddUserEmailAddressSchema struct {
	Email string `form:"email" validate:"required,email"`
}

type AddUserPhoneNumberSchema struct {
	PhoneNumber string `form:"phone_number" validate:"required"`
	CountryCode string `form:"country_code" validate:"required"`
}

type VerifyAuthenticatorSchema struct {
	AuthenticatorID string   `form:"authenticator_id" validate:"required"`
	Codes           []string `form:"codes"            validate:"required,min=2,max=2"`
}

type UpdatePasswordSchema struct {
	CurrentPassword string `form:"current_password"`
	NewPassword     string `form:"new_password"     validate:"required"`
}

type DeleteAccountSchema struct {
	Password string `form:"password" validate:"required"`
}

type RemovePasswordSchema struct {
	CurrentPassword string `form:"current_password" validate:"required"`
}

type UserQueryResult struct {
	// User fields
	UserID                         uint64    `gorm:"column:user_id"`
	UserCreatedAt                  time.Time `gorm:"column:user_created_at"`
	UserUpdatedAt                  time.Time `gorm:"column:user_updated_at"`
	FirstName                      string    `gorm:"column:first_name"`
	LastName                       string    `gorm:"column:last_name"`
	Username                       string    `gorm:"column:username"`
	HasProfilePicture              bool      `gorm:"column:has_profile_picture"`
	ProfilePictureURL              string    `gorm:"column:profile_picture_url"`
	Availability                   string    `gorm:"column:availability"`
	LastPasswordResetAt            time.Time `gorm:"column:last_password_reset_at"`
	SchemaVersion                  string    `gorm:"column:schema_version"`
	Disabled                       bool      `gorm:"column:disabled"`
	PrimaryEmailAddressID          *uint64   `gorm:"column:primary_email_address_id"`
	PrimaryPhoneNumberID           *uint64   `gorm:"column:primary_phone_number_id"`
	SecondFactorPolicy             string    `gorm:"column:second_factor_policy"`
	ActiveOrganizationMembershipID *uint64   `gorm:"column:active_organization_membership_id"`
	ActiveWorkspaceMembershipID    *uint64   `gorm:"column:active_workspace_membership_id"`
	PublicMetadata                 string    `gorm:"column:public_metadata"`
	BackupCodesGenerated           bool      `gorm:"column:backup_codes_generated"`
	HasPassword                    bool      `gorm:"column:has_password"`
	HasPasskeys                    bool      `gorm:"column:has_passkeys"`
	UserEmailAddressesJSON         string    `gorm:"column:user_email_addresses_json"`
	UserPhoneNumbersJSON           string    `gorm:"column:user_phone_numbers_json"`
	SocialConnectionsJSON          string    `gorm:"column:social_connections_json"`
	UserAuthenticatorJSON          string    `gorm:"column:user_authenticator_json"`
	SegmentsJSON                   string    `gorm:"column:segments_json"`
}

type OrganizationMembershipQueryResult struct {
	model.OrganizationMembership
	OrganizationName                    string  `gorm:"column:organization_name"`
	OrganizationImageUrl                string  `gorm:"column:organization_image_url"`
	OrganizationDescription             string  `gorm:"column:organization_description"`
	OrganizationMemberCount             uint32  `gorm:"column:organization_member_count"`
	OrganizationWhitelistedIPs          string  `gorm:"column:organization_whitelisted_ips"`
	OrganizationAutoAssignedWorkspaceID *uint64 `gorm:"column:organization_auto_assigned_workspace_id"`
	OrganizationEnforceMFASetup         bool    `gorm:"column:organization_enforce_mfa"`
	OrganizationEnableIPRestriction     bool    `gorm:"column:organization_enable_ip_restriction"`
	MembershipPublicMetadata            string  `gorm:"column:membership_public_metadata"`
	RolesJSON                           string  `gorm:"column:roles_json"`
	SegmentsJSON                        string  `gorm:"column:segments_json"`
}

type WorkspaceMembershipQueryResult struct {
	model.WorkspaceMembership
	WorkspaceName                       string  `gorm:"column:workspace_name"`
	WorkspaceImageUrl                   string  `gorm:"column:workspace_image_url"`
	WorkspaceDescription                string  `gorm:"column:workspace_description"`
	WorkspaceMemberCount                uint64  `gorm:"column:workspace_member_count"`
	WorkspaceWhitelistedIPs             string  `gorm:"column:workspace_whitelisted_ips"`
	WorkspaceEnforceMFASetup            bool    `gorm:"column:workspace_enforce_mfa"`
	WorkspaceEnableIPRestriction        bool    `gorm:"column:workspace_enable_ip_restriction"`
	OrganizationName                    string  `gorm:"column:organization_name"`
	OrganizationImageUrl                string  `gorm:"column:organization_image_url"`
	OrganizationDescription             string  `gorm:"column:organization_description"`
	OrganizationMemberCount             uint32  `gorm:"column:organization_member_count"`
	OrganizationWhitelistedIPs          string  `gorm:"column:organization_whitelisted_ips"`
	OrganizationAutoAssignedWorkspaceID *uint64 `gorm:"column:organization_auto_assigned_workspace_id"`
	OrganizationEnforceMFASetup         bool    `gorm:"column:organization_enforce_mfa"`
	OrganizationEnableIPRestriction     bool    `gorm:"column:organization_enable_ip_restriction"`
	MembershipPublicMetadata            string  `gorm:"column:membership_public_metadata"`
	RolesJSON                           string  `gorm:"column:roles_json"`
	SegmentsJSON                        string  `gorm:"column:segments_json"`
}
