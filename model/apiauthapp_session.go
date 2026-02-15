package model

import (
	"time"

	"github.com/ilabs/wacht-fe/pkg/idgen"
)

type ApiAuthAppSession struct {
	ID           uint64     `gorm:"primarykey"              json:"id,string"`
	SessionID    uint64     `json:"session_id,string"       gorm:"index;not null"`
	DeploymentID uint64     `json:"deployment_id,string"    gorm:"index;not null"`
	AppSlug      string     `json:"app_slug"                gorm:"type:varchar(255);not null"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

func NewApiAuthAppSession(
	sessionID uint64,
	deploymentID uint64,
	appSlug string,
	expiresAt *time.Time,
) *ApiAuthAppSession {
	return &ApiAuthAppSession{
		ID:           idgen.NextID(),
		SessionID:    sessionID,
		DeploymentID: deploymentID,
		AppSlug:      appSlug,
		ExpiresAt:    expiresAt,
	}
}
