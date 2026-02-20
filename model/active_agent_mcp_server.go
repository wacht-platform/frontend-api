package model

import (
	"encoding/json"
	"time"
)

type ActiveAgentMcpServer struct {
	DeploymentID       uint64          `json:"deployment_id,string" gorm:"primaryKey;not null"`
	ContextGroup       string          `json:"context_group" gorm:"primaryKey;not null"`
	AgentID            uint64          `json:"agent_id,string" gorm:"primaryKey;not null"`
	McpServerID        uint64          `json:"mcp_server_id,string" gorm:"primaryKey;not null"`
	ConnectionMetadata json.RawMessage `json:"connection_metadata,omitempty" gorm:"type:jsonb"`
	CreatedAt          time.Time       `json:"created_at" gorm:"autoCreateTime;not null"`
	UpdatedAt          time.Time       `json:"updated_at" gorm:"autoUpdateTime;not null"`
}

func (ActiveAgentMcpServer) TableName() string {
	return "active_agent_mcp_servers"
}
