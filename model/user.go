package model

import (
	"database/sql/driver"
	"time"

	"gorm.io/datatypes"
)

type VerificationStrategy string

const (
	Otp            VerificationStrategy = "otp"
	OauthGoogle    VerificationStrategy = "oath_google"
	OauthGithub    VerificationStrategy = "oath_github"
	OauthMicrosoft VerificationStrategy = "oauth_microsoft"
	OauthFacebook  VerificationStrategy = "oauth_facebook"
	OauthLinkedIn  VerificationStrategy = "oauth_linkedin"
	OauthDiscord   VerificationStrategy = "oauth_discord"
	OauthApple     VerificationStrategy = "oauth_apple"
)

func (o *VerificationStrategy) Scan(value interface{}) error {
	*o = VerificationStrategy(value.(string))
	return nil
}

func (ct *VerificationStrategy) Value() (driver.Value, error) {
	return string(*ct), nil
}

func (ct VerificationStrategy) GormDataType() string {
	return "text"
}

func (ct VerificationStrategy) GormDBDataType() string {
	return "text"
}

type UserEmailAddress struct {
	Model
	DeploymentID         uint                 `json:"-"                           gorm:"index:idx_deployment_user_email_address_email,unique"`
	UserID               uint                 `json:"-"`
	User                 User                 `json:"-"`
	Email                string               `json:"email"                       gorm:"index:idx_user_email_address_email;index:idx_deployment_user_email_address_email,unique"`
	IsPrimary            bool                 `json:"is_primary"`
	Verified             bool                 `json:"verified"`
	VerifiedAt           time.Time            `json:"verified_at"`
	VerificationStrategy VerificationStrategy `json:"verification_strategy"`
	SocialConnection     *SocialConnection    `json:"social_connection,omitempty"`
}

type SchemaVersion string

const (
	SchemaVersionV1 SchemaVersion = "v1"
	SchemaVersionV2 SchemaVersion = "v2"
)

func (s *SchemaVersion) Scan(value interface{}) error {
	*s = SchemaVersion(value.(string))
	return nil
}

func (s SchemaVersion) Value() (driver.Value, error) {
	return string(s), nil
}

type User struct {
	Model
	FirstName                      string                  `json:"first_name"`
	LastName                       string                  `json:"last_name"`
	Username                       string                  `json:"username"`
	Password                       string                  `json:"-"`
	LastPasswordResetAt            time.Time               `json:"last_password_reset_at"`
	SchemaVersion                  SchemaVersion           `json:"schema_version"`
	Disabled                       bool                    `json:"disabled"`
	PrimaryEmailAddressID          *uint                   `json:"primary_email_address_id"`
	PrimaryPhoneNumberID           *uint                   `json:"primary_phone_number_id"`
	SecondFactorPolicy             SecondFactorPolicy      `json:"second_factor_policy"`
	UserEmailAddresses             []*UserEmailAddress     `json:"user_email_addresses"         gorm:"constraint:OnDelete:CASCADE;"`
	UserPhoneNumbers               []*UserPhoneNumber      `json:"user_phone_numbers"           gorm:"constraint:OnDelete:CASCADE;"`
	SocialConnections              []*SocialConnection     `json:"social_connections,omitempty" gorm:"constraint:OnDelete:CASCADE;"`
	SignIns                        []*Signin               `json:"-"                            gorm:"constraint:OnDelete:CASCADE;"`
	ActiveOrganizationMembershipID *uint                   `json:"active_organization_id"`
	ActiveOrganizationMembership   *OrganizationMembership `json:"active_organization"          gorm:"constraint:OnDelete:CASCADE;"`
	ActiveWorkspaceMembershipID    *uint                   `json:"active_workspace_id"`
	ActiveWorkspaceMembership      *WorkspaceMembership    `json:"active_workspace"             gorm:"constraint:OnDelete:CASCADE;"`
	DeploymentID                   uint                    `json:"-"`
	PublicMetadata                 datatypes.JSONMap       `json:"public_metadata"`
	PrivateMetadata                datatypes.JSONMap       `json:"-"`
	OtpSecret                      string                  `json:"-"`
	BackupCodes                    []string                `json:"-"                            gorm:"type:text[]"`
}
