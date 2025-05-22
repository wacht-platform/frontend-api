package model

import "time"

type DeploymentInvitation struct {
	Model
	DeploymentID *uint       `json:"deployment_id"`
	Deployment   *Deployment `json:"deployment" gorm:"foreignKey:DeploymentID"`
	FirstName    string      `json:"first_name"`
	LastName     string      `json:"last_name"`
	EmailAddress string      `json:"email"`
	Expiry       time.Time   `json:"expiry" gorm:"default:CURRENT_TIMESTAMP + INTERVAL '10 DAY'"`
}
