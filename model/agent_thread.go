package model

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"github.com/lib/pq"
)

type ThreadStatus string

const (
	ThreadStatusIdle            ThreadStatus = "idle"
	ThreadStatusRunning         ThreadStatus = "running"
	ThreadStatusWaitingForInput ThreadStatus = "waiting_for_input"
	ThreadStatusInterrupted     ThreadStatus = "interrupted"
	ThreadStatusCompleted       ThreadStatus = "completed"
	ThreadStatusFailed          ThreadStatus = "failed"
)

func (s *ThreadStatus) Scan(value any) error {
	*s = ThreadStatus(value.(string))
	return nil
}

func (s ThreadStatus) Value() (driver.Value, error) {
	return string(s), nil
}

type AgentThread struct {
	Model
	DeploymentID       uint64          `json:"deployment_id,string"      gorm:"not null;index"`
	ActorID            uint64          `json:"actor_id,string"           gorm:"not null;index"`
	ProjectID          uint64          `json:"project_id,string"         gorm:"not null;index"`
	ProjectName        *string         `json:"project_name,omitempty"    gorm:"->;column:project_name"`
	AgentID            *uint64         `json:"agent_id,string,omitempty" gorm:"-"`
	Title              string          `json:"title"                     gorm:"not null"`
	ThreadPurpose      string          `json:"thread_purpose"            gorm:"not null"`
	Responsibility     *string         `json:"responsibility,omitempty"  gorm:"column:responsibility"`
	Reusable           bool            `json:"reusable"                  gorm:"not null"`
	AcceptsAssignments bool            `json:"accepts_assignments"       gorm:"not null"`
	CapabilityTags     pq.StringArray  `json:"capability_tags"           gorm:"type:text[];not null"`
	LastActivityAt     time.Time       `json:"last_activity_at"          gorm:"not null;default:CURRENT_TIMESTAMP"`
	CompletedAt        *time.Time      `json:"completed_at"`
	Status             ThreadStatus    `json:"status"                    gorm:"not null;default:'idle'"`
	SystemInstructions *string         `json:"system_instructions"       gorm:"type:text"`
	ExecutionState     json.RawMessage `json:"execution_state,omitempty" gorm:"type:jsonb"`
	Metadata           json.RawMessage `json:"metadata"                  gorm:"type:jsonb;not null"`
	ArchivedAt         *time.Time      `json:"archived_at,omitempty"`
}

func (AgentThread) TableName() string {
	return "agent_threads"
}
