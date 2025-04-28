package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
)

type DeploymentRestrictions struct {
	Model
	DeploymentID          uint                             `json:"deployment_id"           gorm:"not null;index"`
	AllowlistEnabled      bool                             `json:"allowlist_enabled"       gorm:"not null"`
	BlocklistEnabled      bool                             `json:"blocklist_enabled"       gorm:"not null"`
	BlockSubaddresses     bool                             `json:"block_subaddresses"      gorm:"not null"`
	BlockDisposableEmails bool                             `json:"block_disposable_emails" gorm:"not null"`
	BlockVoipNumbers      bool                             `json:"block_voip_numbers"      gorm:"not null"`
	CountryRestrictions   CountryRestriction               `json:"country_restrictions"    gorm:"not null"`
	BannedKeywords        []string                         `json:"banned_keywords"         gorm:"type:text[];not null"`
	AllowlistedResources  []string                         `json:"allowlisted_resources"   gorm:"type:text[];not null"`
	BlocklistedResources  []string                         `json:"blocklisted_resources"   gorm:"type:text[];not null"`
	SignUpMode            DeploymentRestrictionsSignUpMode `json:"sign_up_mode"            gorm:"not null"`
}

type CountryRestriction struct {
	Enabled      bool     `json:"enabled"`
	CountryCodes []string `json:"country_codes" gorm:"type:text[]"`
}

func (c *CountryRestriction) Scan(value any) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("value is not a byte slice")
	}

	return json.Unmarshal(bytes, c)
}

func (c CountryRestriction) Value() (driver.Value, error) {
	return json.Marshal(c)
}

func (c CountryRestriction) GormDataType() string {
	return "jsonb"
}

func (c CountryRestriction) GormDBDataType() string {
	return "jsonb"
}

type DeploymentRestrictionsSignUpMode string

const (
	DeploymentRestrictionsSignUpModePublic     DeploymentRestrictionsSignUpMode = "public"
	DeploymentRestrictionsSignUpModeRestricted DeploymentRestrictionsSignUpMode = "restricted"
	DeploymentRestrictionsSignUpModeWaitlist   DeploymentRestrictionsSignUpMode = "waitlist"
)

func (s *DeploymentRestrictionsSignUpMode) Scan(
	value any,
) error {
	*s = DeploymentRestrictionsSignUpMode(
		value.(string),
	)
	return nil
}

func (s DeploymentRestrictionsSignUpMode) Value() (driver.Value, error) {
	return string(s), nil
}

func (s DeploymentRestrictionsSignUpMode) GormDataType() string {
	return "text"
}
