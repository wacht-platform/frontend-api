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
	UserID               uint
	User                 User
	Email                string `gorm:"index:idx_user_email_address_email"`
	IsPrimary            bool
	Verified             bool
	VerifiedAt           time.Time
	VerificationStrategy VerificationStrategy
	SocialConnection     SocialConnection
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
	FirstName           string             `json:"first_name"`
	LastName            string             `json:"last_name"`
	Username            string             `json:"username"`
	Password            string             `json:"password"`
	PrimaryEmailAddress string             `json:"primary_email_address"`
	PhoneNumber         string             `json:"phone_number"`
	SchemaVersion       SchemaVersion      `json:"schema_version"`
	Disabled            bool               `json:"disabled"`
	SecondFactorPolicy  SecondFactorPolicy `json:"second_factor_policy"`
	UserEmailAddresses  []UserEmailAddress `json:"user_email_addresses"`
	SocialConnections   []SocialConnection `json:"social_connections"`
	SignIns             []SignIn           `json:"sign_ins"`
	LastActiveOrgID     uint               `json:"last_active_org_id"`
	DeploymentID        uint               `json:"deployment_id"`
	PublicMetadata      datatypes.JSONMap  `json:"public_metadata"`
	PrivateMetadata     datatypes.JSONMap  `json:"-"`
}
