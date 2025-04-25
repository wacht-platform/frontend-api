package model

type Project struct {
	Model
	Deployments []Deployment
	Name        string `gorm:"not null"`
	ImageURL    string `gorm:"not null"`
}
