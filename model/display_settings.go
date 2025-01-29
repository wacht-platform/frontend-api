package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
)

type ButtonConfig struct {
	BackgroundColor string `json:"background_color"`
	TextColor       string `json:"text_color"`
	BorderRadius    int    `json:"border_radius"`
}

func (b *ButtonConfig) Scan(value any) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("invalid type for ButtonConfig")
	}
	return json.Unmarshal(bytes, b)
}

func (b ButtonConfig) Value() (driver.Value, error) {
	return json.Marshal(b)
}

func (b *ButtonConfig) GormDataType() string {
	return "json"
}

func (b *ButtonConfig) GormDBDataType() string {
	return "jsonb"
}

type InputConfig struct {
	Placeholder string `json:"placeholder"`
	TextColor   string `json:"text_color"`
	BorderColor string `json:"border_color"`
}

func (i *InputConfig) Scan(value any) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("invalid type for InputConfig")
	}
	return json.Unmarshal(bytes, i)
}

func (i InputConfig) Value() (driver.Value, error) {
	return json.Marshal(i)
}

func (i *InputConfig) GormDataType() string {
	return "json"
}

func (i *InputConfig) GormDBDataType() string {
	return "jsonb"
}

type DisplaySettings struct {
	Model
	DeploymentId              uint   `json:"deployment_id"`
	AppName                   string `json:"app_name"`
	PrimaryColor              string `json:"primary_color"`
	TosPageURL                string `json:"tos_page_url"`
	PrivacyPolicyURL          string `json:"privacy_policy_url"`
	SignupTermsStatement      string `json:"signup_terms_statement"`
	SignupTermsStatementShown bool   `json:"signup_terms_statement_shown"`
}
