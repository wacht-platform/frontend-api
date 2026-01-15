package model

import (
	"time"

	"github.com/ilabs/wacht-fe/pkg/idgen"
	"github.com/lib/pq"
)

type AgentSessionIdentifier string

const (
	AgentSessionIdentifierSignin AgentSessionIdentifier = "signin"
	AgentSessionIdentifierStatic AgentSessionIdentifier = "static"
)

type AgentSession struct {
	ID           uint64                 `gorm:"primarykey"              json:"id,string"`
	SessionID    uint64                 `json:"session_id,string" gorm:"index;not null"`
	DeploymentID uint64                 `json:"deployment_id,string" gorm:"index;not null"`
	Identifier   AgentSessionIdentifier `json:"identifier" gorm:"type:varchar(20);not null"`
	ContextGroup string                 `json:"context_group" gorm:"type:varchar(255);not null"`
	AgentIDs     pq.Int64Array          `json:"agent_ids" gorm:"type:bigint[];not null"`
	ExpiresAt    *time.Time             `json:"expires_at,omitempty"`
}

func NewAgentSession(
	sessionID uint64,
	deploymentID uint64,
	identifier AgentSessionIdentifier,
	contextGroup string,
	agentIDs []int64,
	expiresAt *time.Time,
) *AgentSession {
	return &AgentSession{
		ID:           idgen.NextID(),
		SessionID:    sessionID,
		DeploymentID: deploymentID,
		Identifier:   identifier,
		ContextGroup: contextGroup,
		AgentIDs:     agentIDs,
		ExpiresAt:    expiresAt,
	}
}
