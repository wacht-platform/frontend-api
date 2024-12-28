package model

type Deployment struct {
	Model
	MaintenanceMode bool
	Host            string
	PublicKey       string
	Secret          string
	OrgSettings     OrgSettings
	AuthSettings    AuthSettings
	SSOConnections  []SSOConnection
	ProjectID       uint
}
