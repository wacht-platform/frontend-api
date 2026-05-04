package ai

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/wacht-platform/frontend-api/model"
	"github.com/wacht-platform/frontend-api/pkg/idgen"
	"gorm.io/gorm"
)

type pendingApprovalState struct {
	RequestMessageID *string                       `json:"request_message_id,omitempty"`
	Description      string                        `json:"description"`
	Tools            []requestedToolApprovalState  `json:"tools"`
}

type ApprovalSubmissionItem struct {
	ToolName string `json:"tool_name"`
	Mode     string `json:"mode"`
}

type ApprovalSubmission struct {
	RequestMessageID string                   `json:"request_message_id"`
	Approvals        []ApprovalSubmissionItem `json:"approvals"`
}

func (s *Service) ApproveProjectBoardItemTool(
	deploymentID, actorID, projectID, itemID uint64,
	submission *ApprovalSubmission,
) (*model.ProjectTaskBoardItem, error) {
	item, err := s.GetAuthorizedBoardItem(deploymentID, actorID, itemID, false)
	if err != nil {
		return nil, err
	}
	board, err := s.GetProjectBoardByID(deploymentID, actorID, item.BoardID)
	if err != nil {
		return nil, err
	}
	if board.ProjectID != projectID {
		return nil, gorm.ErrRecordNotFound
	}

	if item.PendingApproval == nil {
		return nil, fmt.Errorf("no pending approval on this task")
	}
	var pending pendingApprovalState
	if err := json.Unmarshal(item.PendingApproval, &pending); err != nil {
		return nil, fmt.Errorf("malformed pending_approval: %w", err)
	}
	if pending.RequestMessageID == nil || *pending.RequestMessageID != submission.RequestMessageID {
		return nil, fmt.Errorf("request_message_id does not match the pending approval")
	}

	requestedToolIDs := make(map[string]uint64, len(pending.Tools))
	for _, tool := range pending.Tools {
		var toolID uint64
		if _, err := fmt.Sscanf(tool.ToolID, "%d", &toolID); err != nil {
			return nil, fmt.Errorf("invalid tool_id in pending_approval: %w", err)
		}
		requestedToolIDs[tool.ToolName] = toolID
	}

	seen := make(map[string]struct{}, len(submission.Approvals))
	for _, approval := range submission.Approvals {
		if approval.ToolName == "" {
			return nil, fmt.Errorf("approval tool names must be non-empty")
		}
		if _, ok := seen[approval.ToolName]; ok {
			return nil, fmt.Errorf("approval response contains duplicate tool '%s'", approval.ToolName)
		}
		seen[approval.ToolName] = struct{}{}
		if _, ok := requestedToolIDs[approval.ToolName]; !ok {
			return nil, fmt.Errorf("approval response contains tool '%s' outside the pending approval", approval.ToolName)
		}
		if approval.Mode != "allow_once" && approval.Mode != "allow_always" {
			return nil, fmt.Errorf("invalid approval mode '%s'", approval.Mode)
		}
	}

	var requestMessageID uint64
	if _, err := fmt.Sscanf(submission.RequestMessageID, "%d", &requestMessageID); err != nil {
		return nil, fmt.Errorf("invalid request_message_id: %w", err)
	}

	var requestConversation model.Conversation
	if err := s.db.Where("id = ? AND message_type = ?", requestMessageID, "approval_request").First(&requestConversation).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("approval request conversation not found")
		}
		return nil, err
	}
	askerThreadID := requestConversation.ThreadID

	var assignment model.ProjectTaskBoardItemAssignment
	if err := s.db.Where("board_item_id = ? AND thread_id = ? AND status IN ?",
		item.ID, askerThreadID,
		[]string{"claimed", "in_progress"}).
		Order("created_at DESC").
		First(&assignment).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("no active assignment found for the approval request")
		}
		return nil, err
	}

	now := time.Now()
	enqueuedRouting := false

	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := s.appendApprovalResponseConversation(
			tx,
			askerThreadID,
			item.ID,
			submission.RequestMessageID,
			submission.Approvals,
		); err != nil {
			return err
		}

		for _, approval := range submission.Approvals {
			toolID := requestedToolIDs[approval.ToolName]
			scope := "once"
			if approval.Mode == "allow_always" {
				scope = "thread"
			}
			grantID := idgen.NextID()
			if err := tx.Exec(`
				INSERT INTO approval_grants (
					id, deployment_id, policy_id, actor_id, project_id, thread_id, tool_id,
					granted_by_message_id, grant_scope, status, granted_at, expires_at,
					consumed_at, consumed_by_run_id, metadata
				) VALUES (
					?, ?, NULL, NULL, NULL, ?, ?, NULL, ?, 'active', ?, NULL, NULL, NULL,
					'{}'::jsonb
				)
			`, grantID, deploymentID, askerThreadID, toolID, scope, &now).Error; err != nil {
				return err
			}
		}

		if err := tx.Exec(`
			UPDATE project_task_board_items
			SET pending_approval = NULL,
			    updated_at = ?
			WHERE id = ?
		`, &now, item.ID).Error; err != nil {
			return err
		}

		if err := s.clearThreadPendingApproval(tx, askerThreadID); err != nil {
			return err
		}

		approvalsJSON, err := json.Marshal(submission.Approvals)
		if err != nil {
			return err
		}
		if err := s.enqueueAssignmentResumeEventForApproval(tx, deploymentID, assignment.ID, submission.RequestMessageID, approvalsJSON); err != nil {
			return err
		}
		enqueuedRouting = true
		return nil
	}); err != nil {
		return nil, err
	}

	if enqueuedRouting {
		s.nudgeEventLogDispatcher()
	}

	if err := s.attachProjectTaskSchedule(s.db, item); err != nil {
		return nil, err
	}
	item.PendingApproval = nil
	return item, nil
}

func (s *Service) appendApprovalResponseConversation(
	tx *gorm.DB,
	threadID, boardItemID uint64,
	requestMessageID string,
	approvals []ApprovalSubmissionItem,
) error {
	id := idgen.NextID()
	now := time.Now()
	content, err := json.Marshal(map[string]any{
		"type":               "approval_response",
		"request_message_id": requestMessageID,
		"approvals":          approvals,
	})
	if err != nil {
		return err
	}
	return tx.Exec(`
		INSERT INTO conversations (
			id, thread_id, board_item_id, execution_run_id, timestamp, content, message_type,
			created_at, updated_at, metadata
		) VALUES (
			?, ?, ?, NULL, ?, ?::jsonb, 'approval_response',
			?, ?, NULL
		)
	`, id, threadID, boardItemID, now, string(content), now, now).Error
}

func (s *Service) clearThreadPendingApproval(tx *gorm.DB, threadID uint64) error {
	return tx.Exec(`
		UPDATE agent_threads
		SET execution_state = jsonb_set(
		    COALESCE(execution_state, '{}'::jsonb),
		    '{pending_approval_request}',
		    'null'::jsonb,
		    true
		)
		WHERE id = ?
	`, threadID).Error
}

func (s *Service) enqueueAssignmentResumeEventForApproval(
	tx *gorm.DB,
	deploymentID, assignmentID uint64,
	requestMessageID string,
	approvalsJSON []byte,
) error {
	var assignment model.ProjectTaskBoardItemAssignment
	if err := tx.Where("id = ?", assignmentID).First(&assignment).Error; err != nil {
		return err
	}
	eventLogID := idgen.NextID()
	payload, err := json.Marshal(map[string]any{
		"event_log_id":  fmt.Sprintf("%d", eventLogID),
		"deployment_id": fmt.Sprintf("%d", deploymentID),
		"thread_id":     fmt.Sprintf("%d", assignment.ThreadID),
		"assignment_id": fmt.Sprintf("%d", assignment.ID),
		"board_item_id": fmt.Sprintf("%d", assignment.BoardItemID),
		"kind":          "assignment_execution",
		"summary":       "User responded to the pending approval; resume the assignment.",
		"approvals":     json.RawMessage(approvalsJSON),
	})
	if err != nil {
		return err
	}
	idempotencyKey := fmt.Sprintf("assignment_execution_%d_resume_approval_%s", assignment.ID, requestMessageID)
	return tx.Exec(`
		INSERT INTO event_log (
			id, deployment_id,
			aggregate_type, aggregate_id, event_type, payload, priority,
			publish_subject, publish_status, idempotency_key
		) VALUES (
			?, ?,
			'assignment', ?, 'assignment_execution', ?::jsonb, 20,
			?, 'pending', ?
		)
		ON CONFLICT (idempotency_key) DO NOTHING
	`, eventLogID, deploymentID, assignment.ID, payload, eventLogWorkSubject, idempotencyKey).Error
}
