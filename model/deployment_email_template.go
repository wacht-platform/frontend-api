package model

import (
	"encoding/json"
	"errors"
	"fmt"
)

type EmailTemplate struct {
	TemplateName    string `json:"template_name"`
	TemplateData    string `json:"template_data"`
	TemplateFrom    string `json:"template_from"`
	TemplateReplyTo string `json:"template_reply_to"`
	TemplateSubject string `json:"template_subject"`
}

func (e *EmailTemplate) Scan(value any) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New(fmt.Sprint("Failed to unmarshal JSONB value:", value))
	}

	return json.Unmarshal(bytes, e)
}

func (e *EmailTemplate) Value() (any, error) {
	return json.Marshal(e)
}

func (e *EmailTemplate) GormDataType() string {
	return "jsonb"
}

func (e *EmailTemplate) GormDBDataType() string {
	return "jsonb"
}

type DeploymentEmailTemplate struct {
	Model
	DeploymentID                uint          `json:"deployment_id" gorm:"not null;index"`
	OrganizationInviteTemplate  EmailTemplate `json:"organization_invite_template" gorm:"not null"`
	VerificationCodeTemplate    EmailTemplate `json:"verification_code_template" gorm:"not null"`
	ResetPasswordCodeTemplate   EmailTemplate `json:"reset_password_code_template" gorm:"not null"`
	PrimaryEmailChangeTemplate  EmailTemplate `json:"primary_email_change_template" gorm:"not null"`
	PasswordChangeTemplate      EmailTemplate `json:"password_change_template" gorm:"not null"`
	PasswordRemoveTemplate      EmailTemplate `json:"password_remove_template" gorm:"not null"`
	SignInFromNewDeviceTemplate EmailTemplate `json:"sign_in_from_new_device_template" gorm:"not null"`
	MagicLinkTemplate           EmailTemplate `json:"magic_link_template" gorm:"not null"`
	WaitlistSignupTemplate      EmailTemplate `json:"waitlist_signup_template" gorm:"not null"`
	WaitlistInviteTemplate      EmailTemplate `json:"waitlist_invite_template" gorm:"not null"`
	WorkspaceInviteTemplate     EmailTemplate `json:"workspace_invite_template" gorm:"not null"`
}
