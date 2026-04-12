package model

import (
	"encoding/json"
	"time"
)

type ThreadTaskGraph struct {
	Model
	DeploymentID uint64          `json:"deployment_id,string" gorm:"not null;index"`
	ThreadID     uint64          `json:"thread_id,string" gorm:"not null;index"`
	BoardItemID  *uint64         `json:"board_item_id,omitempty,string" gorm:"column:board_item_id"`
	Version      int             `json:"version" gorm:"not null"`
	Status       string          `json:"status" gorm:"not null"`
	Metadata     json.RawMessage `json:"metadata" gorm:"type:jsonb;not null"`
}

func (ThreadTaskGraph) TableName() string { return "thread_task_graphs" }

type ThreadTaskNode struct {
	Model
	GraphID          uint64          `json:"graph_id,string" gorm:"column:graph_id;not null;index"`
	BoardItemID      *uint64         `json:"board_item_id,omitempty,string" gorm:"column:board_item_id"`
	Title            string          `json:"title" gorm:"not null"`
	Description      *string         `json:"description,omitempty"`
	Status           string          `json:"status" gorm:"not null"`
	Priority         int             `json:"priority" gorm:"not null"`
	OwnerAgentID     *uint64         `json:"owner_agent_id,omitempty,string" gorm:"column:owner_agent_id"`
	AssignedThreadID *uint64         `json:"assigned_thread_id,omitempty,string" gorm:"column:assigned_thread_id"`
	RetryCount       int             `json:"retry_count" gorm:"column:retry_count;not null"`
	MaxRetries       int             `json:"max_retries" gorm:"column:max_retries;not null"`
	Input            json.RawMessage `json:"input,omitempty" gorm:"type:jsonb"`
	Output           json.RawMessage `json:"output,omitempty" gorm:"type:jsonb"`
	Error            json.RawMessage `json:"error,omitempty" gorm:"type:jsonb"`
	LeaseOwner       *string         `json:"lease_owner,omitempty"`
	LeaseUntil       *time.Time      `json:"lease_until,omitempty"`
	CompletedAt      *time.Time      `json:"completed_at,omitempty"`
}

func (ThreadTaskNode) TableName() string { return "thread_task_nodes" }

type ThreadTaskEdge struct {
	GraphID        uint64    `json:"graph_id,string" gorm:"column:graph_id;primaryKey"`
	FromNodeID     uint64    `json:"from_node_id,string" gorm:"column:from_node_id;primaryKey"`
	ToNodeID       uint64    `json:"to_node_id,string" gorm:"column:to_node_id;primaryKey"`
	DependencyType string    `json:"dependency_type" gorm:"column:dependency_type;not null"`
	CreatedAt      time.Time `json:"created_at"`
}

func (ThreadTaskEdge) TableName() string { return "thread_task_edges" }
