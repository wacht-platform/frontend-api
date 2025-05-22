package model

type DeploymentWaitlistUser struct {
	Model
	DeploymentID *uint       `json:"deployment_id"`
	Deployment   *Deployment `json:"deployment" gorm:"foreignKey:DeploymentID"`
	EmailAddress string      `json:"email"`
	FirstName    string      `json:"first_name"`
	LastName     string      `json:"last_name"`
}
