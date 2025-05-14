package model

type DeploymentSmsTemplate struct {
	Model
	DeploymentID              uint64 `json:"deployment_id"                gorm:"not null;index"`
	ResetPasswordCodeTemplate string `json:"reset_password_code_template" gorm:"not null"`
	VerificationCodeTemplate  string `json:"verification_code_template"   gorm:"not null"`
	PasswordChangeTemplate    string `json:"password_change_template"     gorm:"not null"`
	PasswordRemoveTemplate    string `json:"password_remove_template"     gorm:"not null"`
}
