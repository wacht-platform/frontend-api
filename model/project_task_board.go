package model

import (
	"encoding/json"
	"time"
)

type ProjectTaskBoard struct {
	Model
	DeploymentID uint64          `json:"deployment_id,string" gorm:"not null;index"`
	ActorID      uint64          `json:"actor_id,string" gorm:"not null;index"`
	ProjectID    uint64          `json:"project_id,string" gorm:"not null;index"`
	Title        string          `json:"title" gorm:"not null"`
	Status       string          `json:"status" gorm:"not null"`
	Metadata     json.RawMessage `json:"metadata" gorm:"type:jsonb;not null"`
	ArchivedAt   *time.Time      `json:"archived_at,omitempty"`
}

func (ProjectTaskBoard) TableName() string { return "project_task_boards" }

type ProjectTaskBoardItem struct {
	Model
	BoardID          uint64               `json:"board_id,string" gorm:"not null;index"`
	TaskKey          string               `json:"task_key" gorm:"not null"`
	Title            string               `json:"title" gorm:"not null"`
	Description      *string              `json:"description,omitempty"`
	Status           string               `json:"status" gorm:"not null"`
	Priority         string               `json:"priority" gorm:"not null"`
	AssignedThreadID *uint64              `json:"assigned_thread_id,omitempty,string" gorm:"column:assigned_thread_id"`
	Metadata         json.RawMessage      `json:"metadata" gorm:"type:jsonb;not null"`
	Schedule         *ProjectTaskSchedule `json:"schedule,omitempty" gorm:"-"`
	CompletedAt      *time.Time           `json:"completed_at,omitempty"`
	ArchivedAt       *time.Time           `json:"archived_at,omitempty"`
	StateVersion     int64                `json:"state_version,string" gorm:"column:state_version;not null;default:1"`
}

func (ProjectTaskBoardItem) TableName() string { return "project_task_board_items" }

type ProjectTaskBoardItemAssignment struct {
	Model
	BoardItemID     uint64          `json:"board_item_id,string" gorm:"column:board_item_id;not null;index"`
	ThreadID        uint64          `json:"thread_id,string" gorm:"column:thread_id;not null;index"`
	AssignmentRole  string          `json:"assignment_role" gorm:"column:assignment_role;not null"`
	AssignmentOrder int             `json:"assignment_order" gorm:"column:assignment_order;not null"`
	Status          string          `json:"status" gorm:"not null"`
	Instructions    *string         `json:"instructions,omitempty"`
	HandoffFilePath *string         `json:"handoff_file_path,omitempty" gorm:"column:handoff_file_path"`
	Metadata        json.RawMessage `json:"metadata" gorm:"type:jsonb;not null"`
	ResultStatus    *string         `json:"result_status,omitempty" gorm:"column:result_status"`
	ResultSummary   *string         `json:"result_summary,omitempty" gorm:"column:result_summary"`
	ResultPayload   json.RawMessage `json:"result_payload,omitempty" gorm:"type:jsonb;column:result_payload"`
	ClaimedAt       *time.Time      `json:"claimed_at,omitempty"`
	StartedAt       *time.Time      `json:"started_at,omitempty"`
	CompletedAt     *time.Time      `json:"completed_at,omitempty"`
	RejectedAt      *time.Time      `json:"rejected_at,omitempty"`
}

func (ProjectTaskBoardItemAssignment) TableName() string {
	return "project_task_board_item_assignments"
}

type ProjectTaskSchedule struct {
	Model
	TemplateBoardItemID uint64     `json:"template_board_item_id,string" gorm:"column:template_board_item_id;not null;uniqueIndex"`
	Status              string     `json:"status" gorm:"not null"`
	ScheduleKind        string     `json:"schedule_kind" gorm:"column:schedule_kind;not null"`
	IntervalSeconds     *int64     `json:"interval_seconds,omitempty" gorm:"column:interval_seconds"`
	NextRunAt           time.Time  `json:"next_run_at" gorm:"column:next_run_at;not null"`
	LastEnqueuedAt      *time.Time `json:"last_enqueued_at,omitempty" gorm:"column:last_enqueued_at"`
}

func (ProjectTaskSchedule) TableName() string { return "project_task_schedules" }
