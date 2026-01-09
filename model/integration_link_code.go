package model

import (
	"time"
)

type IntegrationLinkCode struct {
	ID              uint64     `json:"id" gorm:"primaryKey"`
	DeploymentID    uint64     `json:"deployment_id" gorm:"not null"`
	ContextGroup    string     `json:"context_group" gorm:"not null;type:varchar(255)"`
	AgentID         uint64     `json:"agent_id" gorm:"not null"`
	IntegrationType string     `json:"integration_type" gorm:"not null"`
	Code            string     `json:"code" gorm:"not null;uniqueIndex"`
	ExpiresAt       time.Time  `json:"expires_at" gorm:"not null"`
	CreatedAt       time.Time  `json:"created_at" gorm:"autoCreateTime"`
	UsedAt          *time.Time `json:"used_at"`
}

func (IntegrationLinkCode) TableName() string {
	return "integration_link_codes"
}
