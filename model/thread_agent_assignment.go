package model

import "time"

type ThreadAgentAssignment struct {
	ThreadID  uint64    `json:"thread_id,string" gorm:"column:thread_id;primaryKey"`
	AgentID   uint64    `json:"agent_id,string" gorm:"column:agent_id;not null"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (ThreadAgentAssignment) TableName() string {
	return "thread_agent_assignments"
}
