package model

import (
	"encoding/json"
	"time"
)

type Actor struct {
	Model
	DeploymentID uint64          `json:"deployment_id,string" gorm:"not null;index"`
	SubjectType  string          `json:"subject_type" gorm:"not null"`
	ExternalKey  string          `json:"external_key" gorm:"not null"`
	DisplayName  *string         `json:"display_name,omitempty"`
	Metadata     json.RawMessage `json:"metadata" gorm:"type:jsonb;not null"`
	ArchivedAt   *time.Time      `json:"archived_at,omitempty" gorm:"-"`
}

func (Actor) TableName() string {
	return "actors"
}
