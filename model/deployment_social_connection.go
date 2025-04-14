package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
)

type SocialConnectionProvider string

const (
	SocialConnectionProviderX         SocialConnectionProvider = "x_oauth"
	SocialConnectionProviderGitHub    SocialConnectionProvider = "github_oauth"
	SocialConnectionProviderGitLab    SocialConnectionProvider = "gitlab_oauth"
	SocialConnectionProviderGoogle    SocialConnectionProvider = "google_oauth"
	SocialConnectionProviderFacebook  SocialConnectionProvider = "facebook_oauth"
	SocialConnectionProviderMicrosoft SocialConnectionProvider = "microsoft_oauth"
	SocialConnectionProviderLinkedIn  SocialConnectionProvider = "linkedin_oauth"
	SocialConnectionProviderDiscord   SocialConnectionProvider = "discord_oauth"
	SocialConnectionProviderApple     SocialConnectionProvider = "apple_oauth"
)

func (p *SocialConnectionProvider) Scan(value interface{}) error {
	*p = SocialConnectionProvider(value.(string))
	return nil
}

func (p SocialConnectionProvider) Value() (driver.Value, error) {
	return string(p), nil
}

func (p SocialConnectionProvider) VerificationStrategy() VerificationStrategy {
	switch p {
	case SocialConnectionProviderX:
		return Otp
	case SocialConnectionProviderGitHub:
		return OauthGithub
	case SocialConnectionProviderGoogle:
		return OauthGoogle
	case SocialConnectionProviderMicrosoft:
		return OauthMicrosoft
	case SocialConnectionProviderFacebook:
		return OauthFacebook
	case SocialConnectionProviderLinkedIn:
		return OauthLinkedIn
	case SocialConnectionProviderDiscord:
		return OauthDiscord
	case SocialConnectionProviderApple:
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
		return errors.New(
			fmt.Sprint("Failed to unmarshal JSONB value:", value),
		)
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
	return "jsonb"
}

func (a *OauthCredentials) GormDBDataType() string {
	return "jsonb"
}

type DeploymentSocialConnection struct {
	Model
	DeploymentID uint                     `json:"deployment_id" gorm:"index:idx_deployment_id_social_connection_provider,unique"`
	Provider     SocialConnectionProvider `json:"provider" gorm:"index:idx_deployment_id_social_connection_provider,unique"`
	Enabled      bool                     `json:"enabled"`
	Credentials  *OauthCredentials        `json:"-"`
}
