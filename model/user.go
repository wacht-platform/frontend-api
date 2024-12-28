package model

import (
	"database/sql/driver"
)

type VerificationStrategy string

const (
	Otp      VerificationStrategy = "otp"
	Google   VerificationStrategy = "google"
	Github   VerificationStrategy = "github"
	Facebook VerificationStrategy = "facebook"
)

func (o *VerificationStrategy) Scan(value interface{}) error {
	*o = VerificationStrategy(value.([]byte))
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
	Email                string
	IsPrimary            bool
	Verified             bool
	VerifiedAt           string
	VerificationStrategy VerificationStrategy
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
	LastActiveOrgID     uint
	DeplymentId         uint
}
