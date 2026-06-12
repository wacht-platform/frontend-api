package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
)

type WaThemeTokens struct {
	Surface           string `json:"surface,omitempty"`
	SurfaceSubtle     string `json:"surface_subtle,omitempty"`
	Background        string `json:"background,omitempty"`
	Canvas            string `json:"canvas,omitempty"`
	Text              string `json:"text,omitempty"`
	TextSecondary     string `json:"text_secondary,omitempty"`
	TextMuted         string `json:"text_muted,omitempty"`
	TextFaint         string `json:"text_faint,omitempty"`
	Border            string `json:"border,omitempty"`
	BorderStrong      string `json:"border_strong,omitempty"`
	Primary           string `json:"primary,omitempty"`
	PrimarySoft       string `json:"primary_soft,omitempty"`
	PrimaryForeground string `json:"primary_foreground,omitempty"`
	Success           string `json:"success,omitempty"`
	SuccessSoft       string `json:"success_soft,omitempty"`
	Info              string `json:"info,omitempty"`
	InfoSoft          string `json:"info_soft,omitempty"`
	Warning           string `json:"warning,omitempty"`
	WarningSoft       string `json:"warning_soft,omitempty"`
	Error             string `json:"error,omitempty"`
	ErrorSoft         string `json:"error_soft,omitempty"`
	Radius            string `json:"radius,omitempty"`
	RadiusLg          string `json:"radius_lg,omitempty"`
	FontSans          string `json:"font_sans,omitempty"`
	FontMono          string `json:"font_mono,omitempty"`
}

// ThemeTokens is the per-deployment `--wa-*` override served to the SDK. The
// column is nullable; a NULL row scans to the zero value (no overrides) and the
// SDK renders with its defaults.
type ThemeTokens struct {
	Light *WaThemeTokens `json:"light,omitempty"`
	Dark  *WaThemeTokens `json:"dark,omitempty"`
}

func (t *ThemeTokens) Scan(value any) error {
	if value == nil {
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("invalid type for ThemeTokens")
	}
	return json.Unmarshal(bytes, t)
}

func (t ThemeTokens) Value() (driver.Value, error) {
	return json.Marshal(t)
}

func (t *ThemeTokens) GormDataType() string {
	return "jsonb"
}

func (t *ThemeTokens) GormDBDataType() string {
	return "jsonb"
}

type DeploymentUISettings struct {
	Model
	DeploymentID                           uint64      `json:"deployment_id,string"                        gorm:"not null;index"`
	AppName                                string      `json:"app_name"                                    gorm:"not null"`
	PrivacyPolicyURL                       string      `json:"privacy_policy_url"                          gorm:"not null"`
	TosPageURL                             string      `json:"tos_page_url"                                gorm:"not null"`
	SignInPageURL                          string      `json:"sign_in_page_url"                            gorm:"not null"`
	SignUpPageURL                          string      `json:"sign_up_page_url"                            gorm:"not null"`
	WaitlistPageURL                        string      `json:"waitlist_page_url"                           gorm:"not null"`
	SupportPageURL                         string      `json:"support_page_url"                            gorm:"not null"`
	AfterLogoClickURL                      string      `json:"after_logo_click_url"                        gorm:"not null"`
	UserProfileURL                         string      `json:"user_profile_url"                            gorm:"not null"`
	OrganizationProfileURL                 string      `json:"organization_profile_url"                    gorm:"not null"`
	CreateOrganizationURL                  string      `json:"create_organization_url"                     gorm:"not null"`
	AfterSignOutOnePageURL                 string      `json:"after_sign_out_one_page_url"                 gorm:"not null"`
	AfterSignOutAllPageURL                 string      `json:"after_sign_out_all_page_url"                 gorm:"not null"`
	AfterSignupRedirectURL                 string      `json:"after_signup_redirect_url"                   gorm:"not null"`
	AfterSigninRedirectURL                 string      `json:"after_signin_redirect_url"                   gorm:"not null"`
	AfterCreateOrganizationRedirectURL     string      `json:"after_create_organization_redirect_url"      gorm:"not null"`
	FaviconImageURL                        string      `json:"favicon_image_url"                           gorm:"not null"`
	DefaultUserProfileImageURL             string      `json:"default_user_profile_image_url"              gorm:"not null"`
	DefaultOrganizationProfileImageURL     string      `json:"default_organization_profile_image_url"      gorm:"not null"`
	DefaultWorkspaceProfileImageURL        string      `json:"default_workspace_profile_image_url"         gorm:"not null;default:''"`
	UseInitialsForUserProfileImage         bool        `json:"use_initials_for_user_profile_image"         gorm:"not null"`
	UseInitialsForOrganizationProfileImage bool        `json:"use_initials_for_organization_profile_image" gorm:"not null"`
	LogoImageURL                           string      `json:"logo_image_url"                              gorm:"not null"`
	SignupTermsStatement                   string      `json:"signup_terms_statement"                      gorm:"not null"`
	SignupTermsStatementShown              bool        `json:"signup_terms_statement_shown"                gorm:"not null"`
	ThemeTokens                            ThemeTokens `json:"theme_tokens"                                gorm:"type:jsonb"`
}
