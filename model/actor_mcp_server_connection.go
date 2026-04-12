package model

import "time"

type ActorMcpServerConnection struct {
	DeploymentID       uint64                `json:"deployment_id,string" gorm:"primaryKey;not null"`
	ActorID            uint64                `json:"actor_id,string" gorm:"primaryKey;not null"`
	McpServerID        uint64                `json:"mcp_server_id,string" gorm:"primaryKey;not null"`
	ConnectionMetadata McpConnectionMetadata `json:"connection_metadata" gorm:"type:jsonb;serializer:json;not null"`
	CreatedAt          time.Time             `json:"created_at"`
	UpdatedAt          time.Time             `json:"updated_at"`
}

func (ActorMcpServerConnection) TableName() string {
	return "actor_mcp_server_connections"
}
