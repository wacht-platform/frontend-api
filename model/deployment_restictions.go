package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
)

type DeploymentRestrictions struct {
	Model
	DeploymentID          uint                             `json:"deployment_id"`
	AllowlistEnabled      bool                             `json:"allowlist_enabled"`
	BlocklistEnabled      bool                             `json:"blocklist_enabled"`
	BlockSubaddresses     bool                             `json:"block_subaddresses"`
	BlockDisposableEmails bool                             `json:"block_disposable_emails"`
	BlockVoipNumbers      bool                             `json:"block_voip"`
	CountryRestrictions   CountryRestriction               `json:"country_restrictions"`
	BannedKeywords        []string                         `json:"banned_keywords" gorm:"type:text[]"`
	AllowlistedResources  []string                         `json:"allowlisted_resources" gorm:"type:text[]"`
	BlocklistedResources  []string                         `json:"blocklisted_resources" gorm:"type:text[]"`
	SignUpMode            DeploymentRestrictionsSignUpMode `json:"sign_up_mode"`
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

func (s *DeploymentRestrictionsSignUpMode) Scan(value any) error {
	*s = DeploymentRestrictionsSignUpMode(value.(string))
	return nil
}

func (s DeploymentRestrictionsSignUpMode) Value() (driver.Value, error) {
	return string(s), nil
}

func (s DeploymentRestrictionsSignUpMode) GormDataType() string {
	return "text"
}
