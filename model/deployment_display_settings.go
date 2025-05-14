package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
)

type LightModeSettings struct {
	PrimaryColor    string `json:"primary_color"    gorm:"not null"`
	BackgroundColor string `json:"background_color" gorm:"not null"`
	TextColor       string `json:"text_color"       gorm:"not null"`
}

func (l *LightModeSettings) Scan(value any) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("invalid type for LightModeSettings")
	}
	return json.Unmarshal(bytes, l)
}

func (l LightModeSettings) Value() (driver.Value, error) {
	return json.Marshal(l)
}

func (l *LightModeSettings) GormDataType() string {
	return "jsonb"
}

func (l *LightModeSettings) GormDBDataType() string {
	return "jsonb"
}

type DarkModeSettings struct {
	PrimaryColor    string `json:"primary_color"    gorm:"not null"`
	BackgroundColor string `json:"background_color" gorm:"not null"`
	TextColor       string `json:"text_color"       gorm:"not null"`
}

func (d *DarkModeSettings) Scan(value any) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("invalid type for DarkModeSettings")
	}
	return json.Unmarshal(bytes, d)
}

func (d DarkModeSettings) Value() (driver.Value, error) {
	return json.Marshal(d)
}

func (d *DarkModeSettings) GormDataType() string {
	return "jsonb"
}

func (d *DarkModeSettings) GormDBDataType() string {
	return "jsonb"
}

type DeploymentUISettings struct {
	Model
	DeploymentID                           uint64            `json:"deployment_id"                               gorm:"not null;index"`
	AppName                                string            `json:"app_name"                                    gorm:"not null"`
	PrivacyPolicyURL                       string            `json:"privacy_policy_url"                          gorm:"not null"`
	TosPageURL                             string            `json:"tos_page_url"                                gorm:"not null"`
	SignInPageURL                          string            `json:"sign_in_page_url"                            gorm:"not null"`
	SignUpPageURL                          string            `json:"sign_up_page_url"                            gorm:"not null"`
	AfterLogoClickURL                      string            `json:"after_logo_click_url"                        gorm:"not null"`
	UserProfileURL                         string            `json:"user_profile_url"                            gorm:"not null"`
	OrganizationProfileURL                 string            `json:"organization_profile_url"                    gorm:"not null"`
	CreateOrganizationURL                  string            `json:"create_organization_url"                     gorm:"not null"`
	AfterSignOutOnePageURL                 string            `json:"after_sign_out_one_page_url"                 gorm:"not null"`
	AfterSignOutAllPageURL                 string            `json:"after_sign_out_all_page_url"                 gorm:"not null"`
	AfterSignupRedirectURL                 string            `json:"after_signup_redirect_url"                   gorm:"not null"`
	AfterSigninRedirectURL                 string            `json:"after_signin_redirect_url"                   gorm:"not null"`
	AfterCreateOrganizationRedirectURL     string            `json:"after_create_organization_redirect_url"      gorm:"not null"`
	FaviconImageURL                        string            `json:"favicon_image_url"                           gorm:"not null"`
	DefaultUserProfileImageURL             string            `json:"default_user_profile_image_url"              gorm:"not null"`
	DefaultOrganizationProfileImageURL     string            `json:"default_organization_profile_image_url"      gorm:"not null"`
	DefaultWorkspaceProfileImageURL        string            `json:"default_workspace_profile_image_url"         gorm:"not null;default:''"`
	UseInitialsForUserProfileImage         bool              `json:"use_initials_for_user_profile_image"         gorm:"not null"`
	UseInitialsForOrganizationProfileImage bool              `json:"use_initials_for_organization_profile_image" gorm:"not null"`
	LogoImageURL                           string            `json:"logo_image_url"                              gorm:"not null"`
	SignupTermsStatement                   string            `json:"signup_terms_statement"                      gorm:"not null"`
	SignupTermsStatementShown              bool              `json:"signup_terms_statement_shown"                gorm:"not null"`
	LightModeSettings                      LightModeSettings `json:"light_mode_settings"                         gorm:"not null"`
	DarkModeSettings                       DarkModeSettings  `json:"dark_mode_settings"                          gorm:"not null"`
}
