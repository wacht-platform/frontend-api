package model

import "time"

// ActorExternalConnection is a per-actor, per-toolkit connection to an
// external integration provider (e.g. Composio, Arcade). Tokens themselves
// live in the provider's vault; we only keep the pointer + status.
type ActorExternalConnection struct {
	DeploymentID      uint64     `json:"deployment_id,string" gorm:"primaryKey;not null"`
	ActorID           uint64     `json:"actor_id,string" gorm:"primaryKey;not null"`
	Provider          string     `json:"provider" gorm:"primaryKey;type:varchar(64);not null"`
	Slug              string     `json:"slug" gorm:"primaryKey;type:varchar(128);not null"`
	ExternalAccountID string     `json:"external_account_id" gorm:"type:varchar(255);not null"`
	Status            string     `json:"status" gorm:"type:varchar(32);not null;default:'pending'"`
	ReturnURL         string     `json:"-" gorm:"type:text"`
	ConnectedAt       *time.Time `json:"connected_at,omitempty"`
	LastRefreshedAt   *time.Time `json:"last_refreshed_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

func (ActorExternalConnection) TableName() string {
	return "actor_external_connections"
}

const (
	ExternalConnectionStatusPending = "pending"
	ExternalConnectionStatusActive  = "active"
	ExternalConnectionStatusExpired = "expired"
	ExternalConnectionStatusFailed  = "failed"
)

const (
	ExternalConnectionProviderComposio = "composio"
)
