package model

import (
	"time"

	"github.com/lib/pq"
	"github.com/wacht-platform/frontend-api/pkg/idgen"
)

type AgentSessionIdentifier string

const (
	AgentSessionIdentifierSignin AgentSessionIdentifier = "signin"
	AgentSessionIdentifierStatic AgentSessionIdentifier = "static"
)

type AgentSession struct {
	ID           uint64                 `gorm:"primarykey" json:"id,string"`
	SessionID    uint64                 `json:"session_id,string" gorm:"index;not null"`
	DeploymentID uint64                 `json:"deployment_id,string" gorm:"index;not null"`
	Identifier   AgentSessionIdentifier `json:"identifier" gorm:"type:varchar(32);not null"`
	ActorID      uint64                 `json:"actor_id,string" gorm:"column:actor_id;not null"`
	AgentIDs     pq.Int64Array          `json:"agent_ids" gorm:"type:bigint[];not null"`
	ExpiresAt    *time.Time             `json:"expires_at,omitempty"`
}

func NewAgentSession(
	sessionID uint64,
	deploymentID uint64,
	identifier AgentSessionIdentifier,
	actorID uint64,
	agentIDs []int64,
	expiresAt *time.Time,
) *AgentSession {
	return &AgentSession{
		ID:           idgen.NextID(),
		SessionID:    sessionID,
		DeploymentID: deploymentID,
		Identifier:   identifier,
		ActorID:      actorID,
		AgentIDs:     agentIDs,
		ExpiresAt:    expiresAt,
	}
}
