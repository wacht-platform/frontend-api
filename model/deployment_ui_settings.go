package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
)

type LightModeSettings struct {
	PrimaryColor    string            `json:"primary_color"                 gorm:"not null"`
	BackgroundColor string            `json:"background_color"              gorm:"not null"`
	TextColor       string            `json:"text_color"                    gorm:"not null"`
	TokenOverrides  *UITokenOverrides `json:"token_overrides,omitempty"`
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
	PrimaryColor    string            `json:"primary_color"                 gorm:"not null"`
	BackgroundColor string            `json:"background_color"              gorm:"not null"`
	TextColor       string            `json:"text_color"                    gorm:"not null"`
	TokenOverrides  *UITokenOverrides `json:"token_overrides,omitempty"`
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

type UITokenOverrides struct {
	SpaceUnit        string `json:"space_unit,omitempty"`
	Card             string `json:"card,omitempty"`
	CardForeground   string `json:"card_foreground,omitempty"`
	Popover          string `json:"popover,omitempty"`
	PopoverForeground string `json:"popover_foreground,omitempty"`
	PrimaryForeground string `json:"primary_foreground,omitempty"`
	Secondary        string `json:"secondary,omitempty"`
	SecondaryForeground string `json:"secondary_foreground,omitempty"`
	Accent           string `json:"accent,omitempty"`
	AccentForeground string `json:"accent_foreground,omitempty"`
	Ring             string `json:"ring,omitempty"`
	Foreground       string `json:"foreground,omitempty"`
	ForegroundInverse string `json:"foreground_inverse,omitempty"`
	SecondaryText    string `json:"secondary_text,omitempty"`
	Muted            string `json:"muted,omitempty"`
	Border           string `json:"border,omitempty"`
	BorderHover      string `json:"border_hover,omitempty"`
	Divider          string `json:"divider,omitempty"`
	InputBackground  string `json:"input_background,omitempty"`
	InputBorder      string `json:"input_border,omitempty"`
	InputFocusBorder string `json:"input_focus_border,omitempty"`
	BackgroundSubtle string `json:"background_subtle,omitempty"`
	BackgroundHover  string `json:"background_hover,omitempty"`
	PrimaryHover     string `json:"primary_hover,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorBackground  string `json:"error_background,omitempty"`
	ErrorBorder      string `json:"error_border,omitempty"`
	Warning          string `json:"warning,omitempty"`
	WarningBackground string `json:"warning_background,omitempty"`
	WarningBorder    string `json:"warning_border,omitempty"`
	WarningText      string `json:"warning_text,omitempty"`
	Success          string `json:"success,omitempty"`
	SuccessBackground string `json:"success_background,omitempty"`
	SuccessBorder    string `json:"success_border,omitempty"`
	Info             string `json:"info,omitempty"`
	InfoBackground   string `json:"info_background,omitempty"`
	RadiusMD         string `json:"radius_md,omitempty"`
	RadiusLG         string `json:"radius_lg,omitempty"`
	RadiusXL         string `json:"radius_xl,omitempty"`
	Radius2XL        string `json:"radius_2xl,omitempty"`
	Radius2XS        string `json:"radius_2xs,omitempty"`
	RadiusXS         string `json:"radius_xs,omitempty"`
	RadiusFull       string `json:"radius_full,omitempty"`
	BorderWidthThin   string `json:"border_width_thin,omitempty"`
	BorderWidthRegular string `json:"border_width_regular,omitempty"`
	ScrollbarTrack   string `json:"scrollbar_track,omitempty"`
	ScrollbarThumb   string `json:"scrollbar_thumb,omitempty"`
	ScrollbarThumbHover string `json:"scrollbar_thumb_hover,omitempty"`
	ShadowColor      string `json:"shadow_color,omitempty"`
	ShadowLightColor string `json:"shadow_light_color,omitempty"`
	ShadowMediumColor string `json:"shadow_medium_color,omitempty"`
	SuccessShadow    string `json:"success_shadow,omitempty"`
	SuccessBackgroundLight string `json:"success_background_light,omitempty"`
	ButtonRipple     string `json:"button_ripple,omitempty"`
	DialogBackdrop   string `json:"dialog_backdrop,omitempty"`
	Space0U          string `json:"space_0u,omitempty"`
	Space1U          string `json:"space_1u,omitempty"`
	Space2U          string `json:"space_2u,omitempty"`
	Space3U          string `json:"space_3u,omitempty"`
	Space4U          string `json:"space_4u,omitempty"`
	Space5U          string `json:"space_5u,omitempty"`
	Space6U          string `json:"space_6u,omitempty"`
	Space7U          string `json:"space_7u,omitempty"`
	Space8U          string `json:"space_8u,omitempty"`
	Space10U         string `json:"space_10u,omitempty"`
	Space12U         string `json:"space_12u,omitempty"`
	Space14U         string `json:"space_14u,omitempty"`
	Space16U         string `json:"space_16u,omitempty"`
	Space24U         string `json:"space_24u,omitempty"`
	FontSize2XS      string `json:"font_size_2xs,omitempty"`
	FontSizeXS       string `json:"font_size_xs,omitempty"`
	FontSizeSM       string `json:"font_size_sm,omitempty"`
	FontSizeMD       string `json:"font_size_md,omitempty"`
	FontSizeLG       string `json:"font_size_lg,omitempty"`
	FontSizeXL       string `json:"font_size_xl,omitempty"`
	FontSize2XL      string `json:"font_size_2xl,omitempty"`
	FontSize3XL      string `json:"font_size_3xl,omitempty"`
	Size8U           string `json:"size_8u,omitempty"`
	Size10U          string `json:"size_10u,omitempty"`
	Size12U          string `json:"size_12u,omitempty"`
	Size18U          string `json:"size_18u,omitempty"`
	Size20U          string `json:"size_20u,omitempty"`
	Size24U          string `json:"size_24u,omitempty"`
	Size32U          string `json:"size_32u,omitempty"`
	Size36U          string `json:"size_36u,omitempty"`
	Size40U          string `json:"size_40u,omitempty"`
	Size45U          string `json:"size_45u,omitempty"`
	Size50U          string `json:"size_50u,omitempty"`
	ShadowSM         string `json:"shadow_sm,omitempty"`
	ShadowMD         string `json:"shadow_md,omitempty"`
	ShadowLG         string `json:"shadow_lg,omitempty"`
	ShadowXL         string `json:"shadow_xl,omitempty"`
	ShadowSuccess    string `json:"shadow_success,omitempty"`
	RingPrimary      string `json:"ring_primary,omitempty"`
	LetterSpacingTight string `json:"letter_spacing_tight,omitempty"`
}

type DeploymentUISettings struct {
	Model
	DeploymentID                           uint64            `json:"deployment_id"                               gorm:"not null;index"`
	AppName                                string            `json:"app_name"                                    gorm:"not null"`
	PrivacyPolicyURL                       string            `json:"privacy_policy_url"                          gorm:"not null"`
	TosPageURL                             string            `json:"tos_page_url"                                gorm:"not null"`
	SignInPageURL                          string            `json:"sign_in_page_url"                            gorm:"not null"`
	SignUpPageURL                          string            `json:"sign_up_page_url"                            gorm:"not null"`
	WaitlistPageURL                        string            `json:"waitlist_page_url"                           gorm:"not null"`
	SupportPageURL                         string            `json:"support_page_url"                            gorm:"not null"`
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
