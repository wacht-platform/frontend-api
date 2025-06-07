package model

// AIAgentTool represents the many-to-many relationship between AI agents and tools
type AIAgentTool struct {
	AgentID uint64 `gorm:"primaryKey"`
	ToolID  uint64 `gorm:"primaryKey"`
}

func (AIAgentTool) TableName() string {
	return "ai_agent_tools"
}

// AIAgentWorkflow represents the many-to-many relationship between AI agents and workflows
type AIAgentWorkflow struct {
	AgentID    uint64 `gorm:"primaryKey"`
	WorkflowID uint64 `gorm:"primaryKey"`
}

func (AIAgentWorkflow) TableName() string {
	return "ai_agent_workflows"
}

// AIAgentKnowledgeBase represents the many-to-many relationship between AI agents and knowledge bases
type AIAgentKnowledgeBase struct {
	AgentID         uint64 `gorm:"primaryKey"`
	KnowledgeBaseID uint64 `gorm:"primaryKey"`
}

func (AIAgentKnowledgeBase) TableName() string {
	return "ai_agent_knowledge_bases"
}
