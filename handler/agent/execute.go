package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/config"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/pkg/idgen"
	"github.com/ilabs/wacht-fe/service"
)

type ExecuteAgentRequest struct {
	AgentName     string        `json:"agent_name,omitempty" form:"agent_name"`
	ExecutionType ExecutionType `json:"execution_type" form:"execution_type"`
}

type ExecutionType struct {
	NewMessage             *NewMessageRequest             `json:"new_message,omitempty"`
	UserInputResponse      *UserInputResponseRequest      `json:"user_input_response,omitempty"`
	PlatformFunctionResult *PlatformFunctionResultRequest `json:"platform_function_result,omitempty"`
	Cancel                 *CancelRequest                 `json:"cancel,omitempty"`
}

type NewMessageRequest struct {
	Message string `json:"message" form:"message"`
}

type UserInputResponseRequest struct {
	Message string `json:"message"`
}

type PlatformFunctionResultRequest struct {
	ExecutionID string                 `json:"execution_id"`
	Result      map[string]interface{} `json:"result"`
}

type CancelRequest struct{}

type ExecuteAgentResponse struct {
	Status         string `json:"status"`
	ConversationID string `json:"conversation_id,omitempty"`
}

type FileData struct {
	Filename string `json:"filename"`
	MimeType string `json:"mime_type"`
	Data     string `json:"data"`
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

var nonURLFriendlyFilenameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func sanitizeUploadFilename(name string) (string, error) {
	sanitized := nonURLFriendlyFilenameChars.ReplaceAllString(name, "_")
	sanitized = strings.Trim(sanitized, "_")
	if sanitized == "" {
		return "", fmt.Errorf("invalid filename")
	}
	return sanitized, nil
}

func (h *Handler) ExecuteAgent(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Session required")
	}

	deployment := handler.GetDeployment(c)

	contextIDStr := c.Params("id")
	contextID, err := strconv.ParseUint(contextIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid context ID")
	}

	var req ExecuteAgentRequest
	var multipartFiles []*multipart.FileHeader

	if err := c.BodyParser(&req); err != nil {
		return handler.SendBadRequest(c, nil, "Invalid request body")
	}

	contentType := c.Get("Content-Type")
	if strings.HasPrefix(contentType, "multipart/form-data") {
		if req.ExecutionType.NewMessage == nil && c.FormValue("message") != "" {
			req.ExecutionType.NewMessage = &NewMessageRequest{
				Message: c.FormValue("message"),
			}
		}

		form, err := c.MultipartForm()
		if err == nil {
			if files, ok := form.File["files"]; ok {
				multipartFiles = files
			}
		}
	}

	agentSessionPtr, err := h.service.GetActiveAgentSession(session.ID, deployment.ID)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active agent session. Please exchange your ticket first.")
	}
	agentSession := *agentSessionPtr

	if agentSession.ExpiresAt != nil && agentSession.ExpiresAt.Before(time.Now()) {
		return handler.SendUnauthorized(c, nil, "Agent session expired")
	}

	contextGroup, err := h.resolveAgentSessionContextGroup(c, &agentSession)
	if err != nil {
		return err
	}
	if contextGroup == "" {
		return handler.SendBadRequest(c, nil, "Context group required in token")
	}

	executionContext, err := h.service.GetContext(deployment.ID, &contextGroup, contextID)
	if err != nil {
		return handler.SendNotFound(c, nil, "Context not found or access denied")
	}
	hasRunningExecution := executionContext.Status == model.ExecutionStatusRunning

	natsService := service.GetNATS()

	var agentID *int64
	if req.AgentName != "" {
		var agent model.AiAgent
		if err := database.Connection.Where(
			"deployment_id = ? AND name = ?",
			deployment.ID, req.AgentName,
		).First(&agent).Error; err != nil {
			return handler.SendBadRequest(c, nil, "Agent not found: "+req.AgentName)
		}

		agentAllowed := slices.Contains(agentSession.AgentIDs, int64(agent.ID))
		if !agentAllowed {
			return handler.SendUnauthorized(c, nil, "Agent not authorized for this session")
		}

		id := int64(agent.ID)
		agentID = &id
	}

	switch {
	case req.ExecutionType.NewMessage != nil:
		return h.handleNewMessage(c, deployment.ID, contextID, agentID, req.ExecutionType.NewMessage, multipartFiles, natsService, hasRunningExecution)

	case req.ExecutionType.UserInputResponse != nil:
		return h.handleUserInputResponse(c, deployment.ID, contextID, agentID, req.ExecutionType.UserInputResponse, natsService, hasRunningExecution)

	case req.ExecutionType.PlatformFunctionResult != nil:
		return h.handlePlatformFunctionResult(c, deployment.ID, contextID, agentID, req.ExecutionType.PlatformFunctionResult, natsService)

	case req.ExecutionType.Cancel != nil:
		return h.handleCancel(c, deployment.ID, contextID, natsService, hasRunningExecution)

	default:
		return handler.SendBadRequest(c, nil, "Invalid execution type")
	}
}

func (h *Handler) handleNewMessage(
	c *fiber.Ctx,
	deploymentID, contextID uint64,
	agentID *int64,
	req *NewMessageRequest,
	multipartFiles []*multipart.FileHeader,
	natsService *service.NatsService,
	hasRunningExecution bool,
) error {
	if req.Message == "" && len(multipartFiles) == 0 {
		return handler.SendBadRequest(c, nil, "Message or files required")
	}

	var storedFiles []StoredFileData
	if len(multipartFiles) > 0 {
		if config.AgentStorageSession == nil {
			return handler.SendInternalServerError(c, nil, "File storage not configured")
		}

		s3Client := s3.New(config.AgentStorageSession)
		bucket := "wacht-agents"

		for _, fileHeader := range multipartFiles {
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

			key := fmt.Sprintf("%d/persistent/%d/uploads/%s",
				deploymentID,
				contextID,
				uniqueFilename,
			)

			contentType := fileHeader.Header.Get("Content-Type")
			if contentType == "" || contentType == "application/octet-stream" {
				buffer := make([]byte, 512)
				_, _ = file.Read(buffer)
				contentType = http.DetectContentType(buffer)
				file.Seek(0, 0)
			}

			_, err = s3Client.PutObject(&s3.PutObjectInput{
				Bucket:      aws.String(bucket),
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
		}
	}

	conversationID := idgen.NextID()

	message := req.Message
	if message == "" && len(storedFiles) > 0 {
		var fileNames []string
		for _, f := range storedFiles {
			fileNames = append(fileNames, f.Filename)
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
		ContextID:   contextID,
		Timestamp:   time.Now(),
		Content:     contentJSON,
		MessageType: "user_message",
	}

	if err := database.Connection.Create(&conversation).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create conversation")
	}

	if hasRunningExecution {
		if err := natsService.SignalAgentExecutionCancellation(
			context.Background(),
			contextID,
		); err != nil {
			return handler.SendInternalServerError(c, err, "Failed to cancel previous execution")
		}
	}

	if err := natsService.PublishAgentExecution(
		context.Background(),
		deploymentID,
		contextID,
		agentID,
		conversationID,
		"new_message",
	); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to publish execution request")
	}

	return handler.SendSuccess(c, ExecuteAgentResponse{
		Status:         "queued",
		ConversationID: strconv.FormatUint(conversationID, 10),
	})
}

func (h *Handler) handleUserInputResponse(
	c *fiber.Ctx,
	deploymentID, contextID uint64,
	agentID *int64,
	req *UserInputResponseRequest,
	natsService *service.NatsService,
	hasRunningExecution bool,
) error {
	if req.Message == "" {
		return handler.SendBadRequest(c, nil, "Message is required")
	}

	conversationID := idgen.NextID()
	content := ConversationContent{
		Type:    "user_message",
		Message: req.Message,
	}

	contentJSON, err := json.Marshal(content)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to serialize content")
	}

	conversation := model.Conversation{
		ID:          conversationID,
		ContextID:   contextID,
		Timestamp:   time.Now(),
		Content:     contentJSON,
		MessageType: "user_message",
	}

	if err := database.Connection.Create(&conversation).Error; err != nil {
		return handler.SendInternalServerError(c, err, "Failed to create conversation")
	}

	if hasRunningExecution {
		if err := natsService.SignalAgentExecutionCancellation(
			context.Background(),
			contextID,
		); err != nil {
			return handler.SendInternalServerError(c, err, "Failed to cancel previous execution")
		}
	}

	if err := natsService.PublishAgentExecution(
		context.Background(),
		deploymentID,
		contextID,
		agentID,
		conversationID,
		"user_input_response",
	); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to publish execution request")
	}

	return handler.SendSuccess(c, ExecuteAgentResponse{
		Status:         "queued",
		ConversationID: strconv.FormatUint(conversationID, 10),
	})
}

func (h *Handler) handlePlatformFunctionResult(
	c *fiber.Ctx,
	deploymentID, contextID uint64,
	agentID *int64,
	req *PlatformFunctionResultRequest,
	natsService *service.NatsService,
) error {
	if req.ExecutionID == "" {
		return handler.SendBadRequest(c, nil, "Execution ID is required")
	}

	if err := natsService.PublishAgentExecutionWithResult(
		context.Background(),
		deploymentID,
		contextID,
		agentID,
		req.ExecutionID,
		req.Result,
	); err != nil {
		return handler.SendInternalServerError(c, err, "Failed to publish execution request")
	}

	return handler.SendSuccess(c, ExecuteAgentResponse{
		Status: "queued",
	})
}

func (h *Handler) handleCancel(
	c *fiber.Ctx,
	deploymentID, contextID uint64,
	natsService *service.NatsService,
	hasRunningExecution bool,
) error {
	result := database.Connection.Model(&model.AgentExecutionContext{}).
		Where("id = ? AND deployment_id = ?", contextID, deploymentID).
		Update("status", model.ExecutionStatusFailed)

	if result.Error != nil {
		return handler.SendInternalServerError(c, result.Error, "Failed to cancel execution")
	}

	if result.RowsAffected == 0 {
		return handler.SendNotFound(c, nil, "Context not found")
	}

	if hasRunningExecution {
		if err := natsService.SignalAgentExecutionCancellation(
			context.Background(),
			contextID,
		); err != nil {
			return handler.SendInternalServerError(c, err, "Failed to cancel execution")
		}
	}

	return handler.SendSuccess(c, ExecuteAgentResponse{
		Status: "cancelled",
	})
}
