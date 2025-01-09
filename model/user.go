package model

import (
	"database/sql/driver"
	"time"
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

type OauthConnection struct {
	Model
	provider string
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
	FirstName           string
	LastName            string
	Username            string
	Password            string
	PrimaryEmailAddress string
	PhoneNumber         string
	SchemaVersion       SchemaVersion
	Disabled            bool
	SecondFactorPolicy  SecondFactorPolicy
	UserEmailAddresses  []UserEmailAddress
	SocialConnections   []SocialConnection
	SignIns             []SignIn
	LastActiveOrgID     uint
	DeploymentID        uint
	TOTPSecret					string
}
