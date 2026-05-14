package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/model"
	"github.com/wacht-platform/frontend-api/pkg/idgen"
	"github.com/wacht-platform/frontend-api/service"
	"gorm.io/gorm"
)

type requestedToolApprovalState struct {
	ToolID          snowflakeID `json:"tool_id"`
	ToolName        string      `json:"tool_name"`
	ToolDescription *string     `json:"tool_description,omitempty"`
}

type snowflakeID int64

func (id *snowflakeID) UnmarshalJSON(data []byte) error {
	var raw string
	if len(data) > 0 && data[0] == '"' {
		if err := json.Unmarshal(data, &raw); err != nil {
			return err
		}
	} else {
		raw = strings.TrimSpace(string(data))
	}
	if raw == "" {
		return fmt.Errorf("expected integer")
	}
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return err
	}
	*id = snowflakeID(parsed)
	return nil
}

func (id snowflakeID) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatInt(int64(id), 10))
}

type toolApprovalDecision struct {
	ToolName string `json:"tool_name"`
	Mode     string `json:"mode"`
}

type threadExecutionStateView struct {
	PendingApprovalRequest json.RawMessage `json:"pending_approval_request"`
}

var nonURLFriendlyFilenameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func sanitizeUploadFilename(name string) (string, error) {
	sanitized := nonURLFriendlyFilenameChars.ReplaceAllString(name, "_")
	sanitized = strings.Trim(sanitized, "_")
	if sanitized == "" {
		return "", fmt.Errorf("invalid filename")
	}
	return sanitized, nil
}

func threadHasPendingApprovalRequest(thread *model.AgentThread) bool {
	if thread == nil || len(thread.ExecutionState) == 0 {
		return false
	}

	var state threadExecutionStateView
	if err := json.Unmarshal(thread.ExecutionState, &state); err != nil {
		return false
	}

	trimmed := strings.TrimSpace(string(state.PendingApprovalRequest))
	return trimmed != "" && trimmed != "null"
}

func parseRunApprovalSelections(form *multipart.Form) ([]ToolApprovalSelection, error) {
	if form == nil {
		return nil, nil
	}
	toolNames := form.Value["approval_tool_name"]
	modes := form.Value["approval_mode"]
	if len(toolNames) != len(modes) {
		return nil, fmt.Errorf("approval_tool_name and approval_mode must have the same length")
	}

	approvals := make([]ToolApprovalSelection, 0, len(toolNames))
	for index := range toolNames {
		toolName := strings.TrimSpace(toolNames[index])
		mode := strings.TrimSpace(modes[index])
		if toolName == "" || mode == "" {
			return nil, fmt.Errorf("approval responses must include non-empty tool names and modes")
		}
		approvals = append(approvals, ToolApprovalSelection{
			ToolName: toolName,
			Mode:     mode,
		})
	}

	return approvals, nil
}

func parseRunRequestForm(c fiber.Ctx) (*NewMessageRequest, *ApprovalResponseRequest, *CancelRequest, []*multipart.FileHeader, error) {
	form, err := c.MultipartForm()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("invalid multipart form")
	}

	message := strings.TrimSpace(c.FormValue("message"))
	requestMessageID := strings.TrimSpace(c.FormValue("request_message_id"))
	cancelRaw := strings.TrimSpace(c.FormValue("cancel"))

	var files []*multipart.FileHeader
	if form != nil {
		files = form.File["files"]
	}

	approvals, err := parseRunApprovalSelections(form)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	actionCount := 0
	var newMessage *NewMessageRequest
	var approvalResponse *ApprovalResponseRequest
	var cancelRequest *CancelRequest

	if message != "" || len(files) > 0 {
		actionCount += 1
		newMessage = &NewMessageRequest{Message: message}
	}
	if requestMessageID != "" || len(approvals) > 0 {
		if requestMessageID == "" {
			return nil, nil, nil, nil, fmt.Errorf("request_message_id is required for approval responses")
		}
		actionCount += 1
		approvalResponse = &ApprovalResponseRequest{
			RequestMessageID: requestMessageID,
			Approvals:        approvals,
		}
	}
	if cancelRaw != "" {
		cancelRequested, err := strconv.ParseBool(cancelRaw)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("invalid cancel value")
		}
		if cancelRequested {
			actionCount += 1
			cancelRequest = &CancelRequest{}
		}
	}

	if actionCount != 1 {
		return nil, nil, nil, nil, fmt.Errorf("invalid execution type")
	}

	return newMessage, approvalResponse, cancelRequest, files, nil
}

func (h *Handler) RunThread(c fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Session required")
	}
	if err := requireMultipartFormRequest(c); err != nil {
		return err
	}

	deployment := handler.GetDeployment(c)
	actorID, agentSession, err := h.getActorScope(c)
	if err != nil {
		return err
	}

	threadIDStr := c.Params("thread_id")
	threadID, err := strconv.ParseUint(threadIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid thread ID")
	}

	newMessage, approvalResponse, cancelRequest, multipartFiles, err := parseRunRequestForm(c)
	if err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	if agentSession.ExpiresAt != nil && agentSession.ExpiresAt.Before(time.Now()) {
		return handler.SendUnauthorized(c, nil, "Agent session expired")
	}

	thread, err := h.service.GetThread(deployment.ID, actorID, threadID)
	if err != nil {
		return handler.SendNotFound(c, nil, "Thread not found or access denied")
	}
	hasInterruptibleExecution := thread.Status == model.ThreadStatusRunning || thread.Status == model.ThreadStatusWaitingForInput

	natsService := service.GetNATS()

	if thread.AgentID == nil || *thread.AgentID == 0 {
		return handler.SendBadRequest(c, nil, "Thread does not have an assigned agent")
	}

	if !sessionHasAgent(agentSession, *thread.AgentID) {
		return handler.SendUnauthorized(c, nil, "Assigned thread agent is not authorized for this session")
	}

	id := int64(*thread.AgentID)
	agentID := &id

	switch {
	case newMessage != nil:
		return h.handleNewMessage(c, deployment.ID, threadID, agentID, thread, newMessage, multipartFiles, natsService)
	case approvalResponse != nil:
		return h.handleApprovalResponse(c, deployment.ID, threadID, agentID, thread, approvalResponse, natsService)
	case cancelRequest != nil:
		return h.handleCancel(c, deployment.ID, threadID, natsService, hasInterruptibleExecution)
	default:
		return handler.SendBadRequest(c, nil, "Invalid execution type")
	}
}
func (h *Handler) handleNewMessage(
	c fiber.Ctx,
	deploymentID, threadID uint64,
	agentID *int64,
	thread *model.AgentThread,
	req *NewMessageRequest,
	multipartFiles []*multipart.FileHeader,
	natsService *service.NatsService,
) error {
	if req.Message == "" && len(multipartFiles) == 0 {
		return handler.SendBadRequest(c, nil, "Message or files required")
	}

	var storedFiles []StoredFileData
	if len(multipartFiles) > 0 {
		storage, err := resolveDeploymentAgentStorage(deploymentID)
		if err != nil {
			return handler.SendInternalServerError(c, err, "Deployment storage not configured")
		}

		for _, fileHeader := range multipartFiles {
			if err := func() error {
				file, err := fileHeader.Open()
				if err != nil {
					return handler.SendInternalServerError(c, err, "Failed to open file: "+fileHeader.Filename)
				}
				defer file.Close()

				safeFilename, err := sanitizeUploadFilename(fileHeader.Filename)
				if err != nil {
					return handler.SendBadRequest(c, nil, "Invalid filename")
				}

				uniqueFilename := fmt.Sprintf("%d_%s", idgen.NextID(), safeFilename)
				key := storage.objectKey(fmt.Sprintf("%d/persistent/%d/uploads/%s", deploymentID, threadID, uniqueFilename))

				contentType := fileHeader.Header.Get("Content-Type")
				if contentType == "" || contentType == "application/octet-stream" {
					buffer := make([]byte, 512)
					n, readErr := io.ReadFull(file, buffer)
					if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
						return handler.SendInternalServerError(c, readErr, "Failed to inspect file: "+fileHeader.Filename)
					}
					contentType = http.DetectContentType(buffer[:n])
					if seeker, ok := file.(io.Seeker); ok {
						if _, err := seeker.Seek(0, io.SeekStart); err != nil {
							return handler.SendInternalServerError(c, err, "Failed to rewind file: "+fileHeader.Filename)
						}
					} else {
						reopened, reopenErr := fileHeader.Open()
						if reopenErr != nil {
							return handler.SendInternalServerError(c, reopenErr, "Failed to reopen file: "+fileHeader.Filename)
						}
						defer reopened.Close()
						file = reopened
					}
				}

				_, err = storage.s3Client.PutObject(&s3.PutObjectInput{
					Bucket:      aws.String(storage.bucket),
					Key:         aws.String(key),
					Body:        file,
					ContentType: aws.String(contentType),
				})
				if err != nil {
					return handler.SendInternalServerError(c, err, "Failed to upload file: "+fileHeader.Filename)
				}

				sizeBytes := uint64(fileHeader.Size)
				storedFiles = append(storedFiles, StoredFileData{
					Filename:  fileHeader.Filename,
					MimeType:  contentType,
					URL:       fmt.Sprintf("/uploads/%s", uniqueFilename),
					SizeBytes: &sizeBytes,
				})
				return nil
			}(); err != nil {
				return err
			}
		}
	}

	conversationID := idgen.NextID()
	message := req.Message
	if message == "" && len(storedFiles) > 0 {
		var fileNames []string
		for _, file := range storedFiles {
			fileNames = append(fileNames, file.Filename)
		}
		message = fmt.Sprintf("I've uploaded the following files: %s", strings.Join(fileNames, ", "))
	}

	content := ConversationContent{
		Type:    "user_message",
		Message: message,
		Files:   storedFiles,
	}

	contentJSON, err := json.Marshal(content)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to serialize content")
	}

	conversation := model.Conversation{
		ID:          conversationID,
		ThreadID:    threadID,
		Timestamp:   time.Now(),
		Content:     contentJSON,
		MessageType: "user_message",
	}

	if err := database.Connection.Create(&conversation).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create conversation")
	}

	if thread.Status == model.ThreadStatusWaitingForInput {
		now := time.Now()
		if err := database.Connection.Model(&model.AgentThread{}).
			Where("id = ? AND deployment_id = ?", threadID, deploymentID).
			Updates(map[string]any{
				"status":           model.ThreadStatusInterrupted,
				"execution_state":  nil,
				"updated_at":       now,
				"last_activity_at": now,
			}).Error; err != nil {
			return handler.SendInternalServerError(c, err, "Failed to reset previous waiting execution")
		}
	}

	if err := h.service.EnqueueUserMessageWork(
		deploymentID,
		threadID,
		agentID,
		conversationID,
	); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to publish execution request")
	}
	natsService.NudgeEventLogDispatcher(context.Background())

	return handler.SendSuccess(c, ExecuteAgentResponse{
		Status:         "queued",
		ConversationID: strconv.FormatUint(conversationID, 10),
	})
}

func (h *Handler) handleApprovalResponse(
	c fiber.Ctx,
	deploymentID, threadID uint64,
	agentID *int64,
	thread *model.AgentThread,
	req *ApprovalResponseRequest,
	natsService *service.NatsService,
) error {
	if thread.Status != model.ThreadStatusWaitingForInput && !threadHasPendingApprovalRequest(thread) {
		return handler.SendBadRequest(c, nil, "Approval responses are only accepted while the thread is waiting for input")
	}

	requestMessageID, err := strconv.ParseUint(req.RequestMessageID, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid request_message_id")
	}

	var requestConversation model.Conversation
	if err := database.Connection.
		Where("id = ? AND thread_id = ? AND message_type = ?", requestMessageID, threadID, "approval_request").
		First(&requestConversation).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return handler.SendBadRequest(c, nil, "request_message_id must reference an approval_request message in this thread")
		}
		return handler.SendInternalServerError(c, err, "Failed to load approval request")
	}

	var pendingApproval struct {
		Description string                       `json:"description"`
		Tools       []requestedToolApprovalState `json:"tools"`
	}
	if err := json.Unmarshal(requestConversation.Content, &pendingApproval); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to parse approval request")
	}

	var recentApprovalResponses []model.Conversation
	if err := database.Connection.
		Where("thread_id = ? AND message_type = ?", threadID, "approval_response").
		Order("id DESC").
		Limit(50).
		Find(&recentApprovalResponses).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to load approval responses")
	}
	for _, conversation := range recentApprovalResponses {
		var responseContent struct {
			RequestMessageID string `json:"request_message_id"`
		}
		if err := json.Unmarshal(conversation.Content, &responseContent); err == nil &&
			responseContent.RequestMessageID == req.RequestMessageID {
			return handler.SendBadRequest(c, nil, "This approval request has already been resolved")
		}
	}

	requestedTools := make(map[string]struct{}, len(pendingApproval.Tools))
	for _, tool := range pendingApproval.Tools {
		requestedTools[tool.ToolName] = struct{}{}
	}

	seen := make(map[string]struct{}, len(req.Approvals))
	decisions := make([]toolApprovalDecision, 0, len(req.Approvals))
	serviceApprovals := make([]service.ToolApprovalSelection, 0, len(req.Approvals))

	for _, approval := range req.Approvals {
		toolName := strings.TrimSpace(approval.ToolName)
		if toolName == "" {
			return handler.SendBadRequest(c, nil, "Approval response tool names must be non-empty")
		}
		if _, ok := seen[toolName]; ok {
			return handler.SendBadRequest(c, nil, "Approval response contains duplicate tools")
		}
		seen[toolName] = struct{}{}

		if _, ok := requestedTools[toolName]; !ok {
			return handler.SendBadRequest(c, nil, "Approval response contains tools outside the pending approval request")
		}
		if approval.Mode != "allow_once" && approval.Mode != "allow_always" {
			return handler.SendBadRequest(c, nil, "Invalid approval mode")
		}

		decisions = append(decisions, toolApprovalDecision{
			ToolName: toolName,
			Mode:     approval.Mode,
		})
		serviceApprovals = append(serviceApprovals, service.ToolApprovalSelection{
			ToolName: toolName,
			Mode:     approval.Mode,
		})
	}

	conversationID := idgen.NextID()
	contentJSON, err := json.Marshal(map[string]any{
		"type":               "approval_response",
		"request_message_id": req.RequestMessageID,
		"approvals":          decisions,
	})
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to serialize content")
	}

	conversation := model.Conversation{
		ID:          conversationID,
		ThreadID:    threadID,
		Timestamp:   time.Now(),
		Content:     contentJSON,
		MessageType: "approval_response",
	}

	if err := database.Connection.Create(&conversation).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create conversation")
	}

	if err := h.service.EnqueueApprovalResponseWork(
		deploymentID,
		threadID,
		agentID,
		req.RequestMessageID,
		serviceApprovals,
	); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to publish execution request")
	}
	natsService.NudgeEventLogDispatcher(context.Background())

	return handler.SendSuccess(c, ExecuteAgentResponse{
		Status:         "queued",
		ConversationID: strconv.FormatUint(conversationID, 10),
	})
}

func (h *Handler) handleCancel(
	c fiber.Ctx,
	deploymentID, threadID uint64,
	natsService *service.NatsService,
	hasInterruptibleExecution bool,
) error {
	result := database.Connection.Model(&model.AgentThread{}).
		Where("id = ? AND deployment_id = ?", threadID, deploymentID).
		Update("status", model.ThreadStatusFailed)

	if result.Error != nil {
		return handler.SendInternalServerError(c, result.Error, "Failed to cancel execution")
	}
	if result.RowsAffected == 0 {
		return handler.SendNotFound(c, nil, "Thread not found")
	}

	if hasInterruptibleExecution {
		if err := natsService.AdvanceAgentExecutionToken(context.Background(), threadID); err != nil {
			return handler.SendInternalServerError(c, err, "Failed to cancel execution")
		}
	}

	return handler.SendSuccess(c, ExecuteAgentResponse{
		Status: "cancelled",
	})
}
