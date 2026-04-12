package model

import (
	"encoding/json"
	"time"
)

type ActorProject struct {
	Model
	DeploymentID        uint64          `json:"deployment_id,string" gorm:"not null;index"`
	ActorID             uint64          `json:"actor_id,string" gorm:"not null;index"`
	Name                string          `json:"name" gorm:"not null"`
	Description         *string         `json:"description,omitempty"`
	Status              string          `json:"status" gorm:"not null"`
	CoordinatorThreadID *uint64         `json:"coordinator_thread_id,omitempty,string" gorm:"column:coordinator_thread_id"`
	ReviewThreadID      *uint64         `json:"review_thread_id,omitempty,string" gorm:"column:review_thread_id"`
	Metadata            json.RawMessage `json:"metadata" gorm:"type:jsonb;not null"`
	ArchivedAt          *time.Time      `json:"archived_at,omitempty"`
}

func (ActorProject) TableName() string {
	return "actor_projects"
}
