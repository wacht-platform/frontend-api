package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
)

type SSOProvider string

const (
	SSOProviderX         SSOProvider = "x_oauth"
	SSOProviderGitHub    SSOProvider = "github_oauth"
	SSOProviderGitLab    SSOProvider = "gitlab_oauth"
	SSOProviderGoogle    SSOProvider = "google_oauth"
	SSOProviderFacebook  SSOProvider = "facebook_oauth"
	SSOProviderMicrosoft SSOProvider = "microsoft_oauth"
	SSOProviderLinkedIn  SSOProvider = "linkedin_oauth"
	SSOProviderDiscord   SSOProvider = "discord_oauth"
	SSOProviderApple		 SSOProvider = "apple_oauth"
)

func (p *SSOProvider) Scan(value interface{}) error {
	*p = SSOProvider(value.(string))
	return nil
}

func (p SSOProvider) Value() (driver.Value, error) {
	return string(p), nil
}

func (p SSOProvider) VerificationStrategy() VerificationStrategy {
	switch p {
	case SSOProviderX:
		return Otp
	case SSOProviderGitHub:
		return OauthGithub
	case SSOProviderGoogle:
		return OauthGoogle
	case SSOProviderMicrosoft:
		return OauthMicrosoft
	case SSOProviderFacebook:
		return OauthFacebook
	case SSOProviderLinkedIn:
		return OauthLinkedIn
	case SSOProviderDiscord:
		return OauthDiscord
	case SSOProviderApple:
		return OauthApple
	}
	return ""
}

type OauthCredentials struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
}

func (o *OauthCredentials) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New(fmt.Sprint("Failed to unmarshal JSONB value:", value))
	}

	result := OauthCredentials{}
	err := json.Unmarshal(bytes, &result)
	*o = OauthCredentials(result)
	return err
}

func (o *OauthCredentials) Value() (driver.Value, error) {
	return json.Marshal(o)
}

func (o *OauthCredentials) GormDataType() string {
	return "json"
}

func (a *OauthCredentials) GormDBDataType() string {
	return "jsonb"
}

type SSOConnection struct {
	Model
	DeploymentID         uint        `json:"deployment_id"`
	Provider             SSOProvider `json:"provider"`
	Enabled              bool        `json:"enabled"`
	UserDefinedScopes    []string    `gorm:"type:text[]" json:"user_defined_scopes"`
	CustomCredentialsSet bool        `json:"custom_credentials_set"`
}
