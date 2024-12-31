package model

type Deployment struct {
	Model
	MaintenanceMode bool
	Host            string
	PublishableKey  string
	Secret          string
	OrgSettings     OrgSettings
	AuthSettings    AuthSettings
	SSOConnections  []SSOConnection
	ProjectID       uint
	KepPair         DeploymentKeyPair
}
