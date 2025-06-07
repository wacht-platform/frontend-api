package model

import (
	"database/sql/driver"
	"time"

	"github.com/lib/pq"
	"gorm.io/datatypes"
)

type SchemaVersion string

const (
	SchemaVersionV1 SchemaVersion = "v1"
	SchemaVersionV2 SchemaVersion = "v2"
)

func (s *SchemaVersion) Scan(value any) error {
	*s = SchemaVersion(value.(string))
	return nil
}

func (s SchemaVersion) Value() (driver.Value, error) {
	return string(s), nil
}

type UserAvailability string

const (
	UserAvailabilityAvailable UserAvailability = "available"
	UserAvailabilityBusy      UserAvailability = "busy"
	UserAvailabilityAway      UserAvailability = "away"
)

func (u *UserAvailability) Scan(value any) error {
	*u = UserAvailability(value.(string))
	return nil
}

func (u UserAvailability) Value() (driver.Value, error) {
	return string(u), nil
}

type User struct {
	Model
	FirstName                      string                  `json:"first_name"                      gorm:"not null"`
	HasProfilePicture              bool                    `json:"has_profile_picture"             gorm:"not null"`
	ProfilePictureURL              string                  `json:"profile_picture_url"             gorm:"not null"`
	LastName                       string                  `json:"last_name"                       gorm:"not null"`
	Username                       string                  `json:"username"                        gorm:"not null"`
	Password                       string                  `json:"-" gorm:"select:false"`
	Availability                   UserAvailability        `json:"availability"                    gorm:"default:away;not null"`
	LastPasswordResetAt            time.Time               `json:"last_password_reset_at"`
	SchemaVersion                  SchemaVersion           `json:"schema_version"                  gorm:"not null"`
	Disabled                       bool                    `json:"disabled"                        gorm:"not null"`
	PrimaryEmailAddressID          *uint64                 `json:"primary_email_address_id,string"`
	PrimaryPhoneNumberID           *uint64                 `json:"primary_phone_number_id,string"`
	PrimaryPhoneNumber             *UserPhoneNumber        `json:"primary_phone_number"            gorm:"constraint:OnDelete:SET NULL;foreignKey:PrimaryPhoneNumberID"`
	PrimaryEmailAddress            *UserEmailAddress       `json:"primary_email_address"           gorm:"constraint:OnDelete:SET NULL;foreignKey:PrimaryEmailAddressID"`
	SecondFactorPolicy             SecondFactorPolicy      `json:"second_factor_policy"            gorm:"not null"`
	UserEmailAddresses             []UserEmailAddress      `json:"user_email_addresses"            gorm:"constraint:OnDelete:CASCADE;"`
	UserPhoneNumbers               []UserPhoneNumber       `json:"user_phone_numbers"              gorm:"constraint:OnDelete:CASCADE;"`
	UserAuthenticator              *UserAuthenticator      `json:"user_authenticator"              gorm:"constraint:OnDelete:CASCADE;"`
	SocialConnections              []SocialConnection      `json:"social_connections,omitempty"    gorm:"constraint:OnDelete:CASCADE;"`
	SignIns                        []*Signin               `json:"-"                               gorm:"constraint:OnDelete:CASCADE;"`
	ActiveOrganizationMembershipID *uint64                 `json:"active_organization_membership_id,string"`
	ActiveOrganizationMembership   *OrganizationMembership `json:"active_organization"             gorm:"constraint:OnDelete:SET NULL;"`
	ActiveWorkspaceMembershipID    *uint64                 `json:"active_workspace_membership_id,string"`
	ActiveWorkspaceMembership      *WorkspaceMembership    `json:"active_workspace"                gorm:"constraint:OnDelete:SET NULL;"`
	DeploymentID                   uint64                  `json:"-"                               gorm:"not null;select:false"`
	PublicMetadata                 datatypes.JSONMap       `json:"public_metadata"                 gorm:"not null"`
	PrivateMetadata                datatypes.JSONMap       `json:"-"                               gorm:"not null"`
	OtpSecret                      string                  `json:"-"                               gorm:"not null"`
	BackupCodesGenerated           bool                    `json:"backup_codes_generated"          gorm:"not null"`
	BackupCodes                    pq.StringArray          `json:"-"                               gorm:"type:text[]"`
}

type PublicUserData struct {
	Model
	FirstName             string            `json:"first_name"                      gorm:"not null"`
	HasProfilePicture     bool              `json:"has_profile_picture"             gorm:"not null"`
	ProfilePictureURL     string            `json:"profile_picture_url"             gorm:"not null"`
	LastName              string            `json:"last_name"                       gorm:"not null"`
	Username              string            `json:"username"                        gorm:"not null"`
	Availability          UserAvailability  `json:"availability"                    gorm:"default:away;not null"`
	PrimaryEmailAddressID *uint64           `json:"primary_email_address_id"`
	PrimaryPhoneNumberID  *uint64           `json:"-"`
	PrimaryPhoneNumber    *UserPhoneNumber  `json:"primary_phone_number" gorm:"foreignKey:PrimaryPhoneNumberID;references:ID"`
	PrimaryEmailAddress   *UserEmailAddress `json:"primary_email_address" gorm:"foreignKey:PrimaryEmailAddressID;references:ID"`
}

func (PublicUserData) TableName() string {
	return "users"
}
