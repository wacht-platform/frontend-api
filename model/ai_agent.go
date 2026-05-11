package model

// AiAgent is the minimal GORM-side view of an agent. The Rust platform-api
// owns the full schema (model overrides, hooks, approval rules, etc.) and
// queries the table directly; this struct only exists so AutoMigrate keeps
// the table shape we share. Add fields here only when Go code needs them.
type AiAgent struct {
	Model
	DeploymentID uint64 `json:"deployment_id,string" gorm:"not null;index"`
	Name         string `json:"name" gorm:"not null"`
	Description  string `json:"description"`
}

func (AiAgent) TableName() string {
	return "ai_agents"
}
