package agent

import (
	"encoding/json"
	"time"
)

type CreateContextRequest struct {
	Title              string  `json:"title" validate:"required"`
	SystemInstructions *string `json:"system_instructions,omitempty"`
}

type ListContextsRequest struct {
	Limit  int    `query:"limit"`
	Offset int    `query:"offset"`
	Status string `query:"status"`
}

type ListContextsResponse struct {
	Data    []interface{} `json:"data"`
	HasMore bool          `json:"has_more"`
	Limit   *int          `json:"limit,omitempty"`
	Offset  *int          `json:"offset,omitempty"`
}

// ConversationMessage represents a message in the conversation
type ConversationMessage struct {
	ID        string          `json:"id"`
	Role      string          `json:"role"`
	Content   json.RawMessage `json:"content"`
	Timestamp time.Time       `json:"timestamp"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

type ListMessagesResponse struct {
	Data    []ConversationMessage `json:"data"`
	HasMore bool                  `json:"has_more"`
}