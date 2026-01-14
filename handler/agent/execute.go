package agent

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/pkg/idgen"
	"github.com/ilabs/wacht-fe/service"
)

type ExecuteAgentRequest struct {
	AgentName     string        `json:"agent_name,omitempty"`
	ExecutionType ExecutionType `json:"execution_type"`
}

type ExecutionType struct {
	NewMessage             *NewMessageRequest             `json:"new_message,omitempty"`
	UserInputResponse      *UserInputResponseRequest      `json:"user_input_response,omitempty"`
	PlatformFunctionResult *PlatformFunctionResultRequest `json:"platform_function_result,omitempty"`
	Cancel                 *CancelRequest                 `json:"cancel,omitempty"`
}

type NewMessageRequest struct {
	Message string `json:"message"`
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

type ConversationContent struct {
	Type       string  `json:"type"`
	Message    string  `json:"message"`
	SenderName *string `json:"sender_name,omitempty"`
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
	if err := c.BodyParser(&req); err != nil {
		return handler.SendBadRequest(c, nil, "Invalid request body")
	}

	var agentSession model.AgentSession
	if err := database.Connection.Where(
		"session_id = ? AND deployment_id = ? AND deleted_at IS NULL",
		session.ID, deployment.ID,
	).First(&agentSession).Error; err != nil {
		return handler.SendUnauthorized(c, nil, "No active agent session. Please exchange your ticket first.")
	}

	if agentSession.ExpiresAt != nil && agentSession.ExpiresAt.Before(time.Now()) {
		return handler.SendUnauthorized(c, nil, "Agent session expired")
	}

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

		// Verify agent is in allowed list
		agentAllowed := slices.Contains(agentSession.AgentIDs, int64(agent.ID))
		if !agentAllowed {
			return handler.SendUnauthorized(c, nil, "Agent not authorized for this session")
		}

		id := int64(agent.ID)
		agentID = &id
	}

	switch {
	case req.ExecutionType.NewMessage != nil:
		return h.handleNewMessage(c, deployment.ID, contextID, agentID, req.ExecutionType.NewMessage, natsService)

	case req.ExecutionType.UserInputResponse != nil:
		return h.handleUserInputResponse(c, deployment.ID, contextID, agentID, req.ExecutionType.UserInputResponse, natsService)

	case req.ExecutionType.PlatformFunctionResult != nil:
		return h.handlePlatformFunctionResult(c, deployment.ID, contextID, agentID, req.ExecutionType.PlatformFunctionResult, natsService)

	case req.ExecutionType.Cancel != nil:
		return h.handleCancel(c, deployment.ID, contextID)

	default:
		return handler.SendBadRequest(c, nil, "Invalid execution type")
	}
}

func (h *Handler) handleNewMessage(
	c *fiber.Ctx,
	deploymentID, contextID uint64,
	agentID *int64,
	req *NewMessageRequest,
	natsService *service.NatsService,
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

	return handler.SendSuccess(c, ExecuteAgentResponse{
		Status: "cancelled",
	})
}
