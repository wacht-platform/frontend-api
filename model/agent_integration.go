package model

// AgentIntegration represents an integration configured in the console
type AgentIntegration struct {
	Model
	DeploymentID    uint64 `json:"deployment_id,string" gorm:"not null;index"`
	AgentID         uint64 `json:"agent_id,string" gorm:"not null;index"`
	IntegrationType string `json:"integration_type" gorm:"not null"`
	Name            string `json:"name" gorm:"not null"`
	Config          string `json:"config" gorm:"type:jsonb"`
}

func (AgentIntegration) TableName() string {
	return "agent_integrations"
}
