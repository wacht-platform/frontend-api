package model

import "time"

type AiAgentMcpServer struct {
	DeploymentID uint64    `json:"deployment_id,string" gorm:"primaryKey;not null"`
	AgentID      uint64    `json:"agent_id,string" gorm:"primaryKey;not null"`
	McpServerID  uint64    `json:"mcp_server_id,string" gorm:"primaryKey;not null"`
	CreatedAt    time.Time `json:"created_at" gorm:"autoCreateTime;not null"`
	UpdatedAt    time.Time `json:"updated_at" gorm:"autoUpdateTime;not null"`
}

func (AiAgentMcpServer) TableName() string {
	return "ai_agent_mcp_servers"
}
