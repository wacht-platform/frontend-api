package model

// ActiveAgentIntegration links an integration to a context_group
type ActiveAgentIntegration struct {
	Model
	DeploymentID  uint64 `json:"deployment_id,string" gorm:"not null;index"`
	AgentID       uint64 `json:"agent_id,string" gorm:"not null;index"`
	IntegrationID uint64 `json:"integration_id,string" gorm:"not null;index"`
	ContextGroup  string `json:"context_group" gorm:"not null;index"`
}

func (ActiveAgentIntegration) TableName() string {
	return "active_agent_integrations"
}
