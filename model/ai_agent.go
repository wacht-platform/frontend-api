package model

// AiAgent represents an AI agent configuration
type AiAgent struct {
	Model
	DeploymentID  uint64 `json:"deployment_id,string" gorm:"not null;index"`
	Name          string `json:"name" gorm:"not null"`
	Description   string `json:"description"`
	Configuration string `json:"configuration" gorm:"type:jsonb"`
}

func (AiAgent) TableName() string {
	return "ai_agents"
}
