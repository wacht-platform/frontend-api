package ai

import (
	"encoding/json"
	"time"

	"github.com/wacht-platform/frontend-api/model"
)

type ActorSummary struct {
	ID          uint64  `json:"id,string"`
	DisplayName *string `json:"display_name,omitempty"`
	SubjectType string  `json:"subject_type"`
	ExternalKey string  `json:"external_key"`
}

type Agent struct {
	ID          uint64  `json:"id,string"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	ChildAgents []Agent `json:"child_agents,omitempty"`
}

type AgentSessionResponse struct {
	SessionID uint64       `json:"session_id,string"`
	Actor     ActorSummary `json:"actor"`
	Agents    []Agent      `json:"agents"`
}

type ActorMcpServerSummary struct {
	ID                     uint64     `json:"id,string"`
	Name                   string     `json:"name"`
	Endpoint               string     `json:"endpoint"`
	AuthType               string     `json:"auth_type"`
	RequiresUserConnection bool       `json:"requires_user_connection"`
	ConnectionStatus       string     `json:"connection_status"`
	ConnectedAt            *time.Time `json:"connected_at,omitempty"`
	ExpiresAt              *time.Time `json:"expires_at,omitempty"`
}

type ActorMcpServerConnectResponse struct {
	AuthURL string `json:"auth_url"`
}

type ConversationMessage struct {
	ID        string          `json:"id"`
	Content   json.RawMessage `json:"content"`
	Timestamp time.Time       `json:"timestamp"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

type ListMessagesResponse struct {
	Data    []ConversationMessage `json:"data"`
	HasMore bool                  `json:"has_more"`
}

type CreateActorProjectRequest struct {
	Name        string  `form:"name" validate:"required"`
	AgentID     *uint64 `form:"agent_id" validate:"required"`
	Description *string `form:"description"`
	Status      *string `form:"status"`
}

type UpdateActorProjectRequest struct {
	Name        *string `form:"name"`
	Description *string `form:"description"`
	Status      *string `form:"status"`
}

type CreateAgentThreadRequest struct {
	Title              string          `form:"title" validate:"required"`
	AgentID            *uint64         `form:"agent_id" validate:"required"`
	SystemInstructions *string         `form:"system_instructions"`
	ThreadPurpose      *string         `form:"thread_purpose"`
	Responsibility     *string         `form:"responsibility"`
	Reusable           *bool           `form:"reusable"`
	AcceptsAssignments *bool           `form:"accepts_assignments"`
	CapabilityTags     []string        `form:"capability_tags"`
	Metadata           json.RawMessage `form:"metadata"`
}

type UpdateAgentThreadRequest struct {
	Title              *string `form:"title"`
	AgentID            *uint64 `form:"agent_id"`
	SystemInstructions *string `form:"system_instructions"`
}

type CreateProjectTaskBoardItemRequest struct {
	Title           string  `form:"title"`
	Description     *string `form:"description"`
	Status          *string `form:"status"`
	Priority        *string `form:"priority"`
	ScheduleKind    *string `form:"schedule_kind"`
	NextRunAt       *string `form:"next_run_at"`
	IntervalSeconds *int64  `form:"interval_seconds"`
}

type UpdateProjectTaskBoardItemRequest struct {
	Title           *string `form:"title"`
	Description     *string `form:"description"`
	Status          *string `form:"status"`
	Priority        *string `form:"priority"`
	ScheduleKind    *string `form:"schedule_kind"`
	NextRunAt       *string `form:"next_run_at"`
	IntervalSeconds *int64  `form:"interval_seconds"`
	ClearSchedule   *bool   `form:"clear_schedule"`
}

type ProjectTaskBoardItemDetail struct {
	Item        model.ProjectTaskBoardItem             `json:"item"`
	Events      []model.ProjectTaskBoardItemEvent      `json:"events"`
	Assignments []model.ProjectTaskBoardItemAssignment `json:"assignments"`
}

type AppendProjectTaskBoardItemJournalRequest struct {
	Summary      string  `form:"summary"`
	Details      *string `form:"details"`
	BodyMarkdown *string `form:"body_markdown"`
}

type UploadedTaskWorkspaceFile struct {
	Path         string `json:"path"`
	Name         string `json:"name"`
	OriginalName string `json:"original_name"`
	MimeType     string `json:"mime_type"`
	SizeBytes    uint64 `json:"size_bytes"`
}

type UploadedProjectWorkspaceFile struct {
	Path         string `json:"path"`
	Name         string `json:"name"`
	OriginalName string `json:"original_name"`
	MimeType     string `json:"mime_type"`
	SizeBytes    uint64 `json:"size_bytes"`
}

type UploadTaskWorkspaceFilesResponse struct {
	Files []UploadedTaskWorkspaceFile `json:"files"`
}

type NewMessageRequest struct {
	Message string `form:"message"`
}

type ToolApprovalSelection struct {
	ToolName string `form:"approval_tool_name"`
	Mode     string `form:"approval_mode"`
}

type ApprovalResponseRequest struct {
	RequestMessageID string `form:"request_message_id"`
	Approvals        []ToolApprovalSelection
}

type CancelRequest struct{}

type ExecuteAgentResponse struct {
	Status         string `json:"status"`
	ConversationID string `json:"conversation_id,omitempty"`
}

type StoredFileData struct {
	Filename  string  `json:"filename"`
	MimeType  string  `json:"mime_type"`
	URL       string  `json:"url"`
	SizeBytes *uint64 `json:"size_bytes,omitempty"`
}

type ConversationContent struct {
	Type       string           `json:"type"`
	Message    string           `json:"message"`
	SenderName *string          `json:"sender_name,omitempty"`
	Files      []StoredFileData `json:"files,omitempty"`
}

type ThreadTaskGraphSummary struct {
	GraphID         string  `json:"graph_id"`
	GraphStatus     string  `json:"graph_status"`
	TotalNodes      int64   `json:"total_nodes"`
	PendingNodes    int64   `json:"pending_nodes"`
	ReadyNodes      int64   `json:"ready_nodes"`
	InProgressNodes int64   `json:"in_progress_nodes"`
	CompletedNodes  int64   `json:"completed_nodes"`
	FailedNodes     int64   `json:"failed_nodes"`
	CancelledNodes  int64   `json:"cancelled_nodes"`
	ProgressPercent float64 `json:"progress_percent"`
}

type ThreadTaskGraphBundle struct {
	Graph   model.ThreadTaskGraph   `json:"graph"`
	Nodes   []model.ThreadTaskNode  `json:"nodes"`
	Edges   []model.ThreadTaskEdge  `json:"edges"`
	Summary *ThreadTaskGraphSummary `json:"summary,omitempty"`
}

type ThreadTaskGraphsResponse struct {
	Data       []ThreadTaskGraphBundle `json:"data"`
	Limit      int                     `json:"limit"`
	HasMore    bool                    `json:"has_more"`
	NextCursor string                  `json:"next_cursor,omitempty"`
}

type ThreadEventsResponse struct {
	Data       []model.ThreadEvent `json:"data"`
	Limit      int                 `json:"limit"`
	HasMore    bool                `json:"has_more"`
	NextCursor string              `json:"next_cursor,omitempty"`
}

type ThreadAssignmentsResponse struct {
	Data       []model.ProjectTaskBoardItemAssignment `json:"data"`
	Limit      int                                    `json:"limit"`
	HasMore    bool                                   `json:"has_more"`
	NextCursor string                                 `json:"next_cursor,omitempty"`
}

type ActorProjectsResponse struct {
	Data       []model.ActorProject `json:"data"`
	Limit      int                  `json:"limit"`
	HasMore    bool                 `json:"has_more"`
	NextCursor string               `json:"next_cursor,omitempty"`
}

type ProjectThreadsResponse struct {
	Data       []model.AgentThread `json:"data"`
	Limit      int                 `json:"limit"`
	HasMore    bool                `json:"has_more"`
	NextCursor string              `json:"next_cursor,omitempty"`
}

type ProjectTaskBoardItemsResponse struct {
	Data       []model.ProjectTaskBoardItem `json:"data"`
	Limit      int                          `json:"limit"`
	HasMore    bool                         `json:"has_more"`
	NextCursor string                       `json:"next_cursor,omitempty"`
}
