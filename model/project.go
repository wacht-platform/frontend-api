package model

type Project struct {
	Model
	Deployments []Deployment
	Name        string
	ImageURL    string
}
