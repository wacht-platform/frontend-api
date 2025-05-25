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
	OauthFacebook  VerificationStrategy = "oauth_facebook"
	OauthLinkedIn  VerificationStrategy = "oauth_linkedin"
	OauthDiscord   VerificationStrategy = "oauth_discord"
	OauthApple     VerificationStrategy = "oauth_apple"
)

func (o *VerificationStrategy) Scan(value any) error {
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
	DeploymentID         uint64               `json:"-" gorm:"index:idx_deployment_user_email_address_email,unique"`
	Deployment           Deployment           `json:"-" gorm:"foreignKey:DeploymentID"`
	UserID               *uint64              `json:"-" gorm:"index:idx_deployment_user_email_address_email,unique"`
	User                 User                 `json:"-" gorm:"foreignKey:UserID"`
	EmailAddress         string               `json:"email" gorm:"index:idx_user_email_address_email;index:idx_deployment_user_email_address_email,unique"`
	IsPrimary            bool                 `json:"is_primary" gorm:"not null"`
	Verified             bool                 `json:"verified" gorm:"not null"`
	VerifiedAt           time.Time            `json:"verified_at"`
	VerificationStrategy VerificationStrategy `json:"verification_strategy"`
	SocialConnection     *SocialConnection    `json:"social_connection,omitempty"`
}
