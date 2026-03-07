package webhookapp

import (
	"github.com/wacht-platform/frontend-api/model"
)

type EndpointWithSubscriptions struct {
	model.WebhookEndpoint
	SubscribedEvents []string            `json:"subscribed_events"`
	Subscriptions    []EventSubscription `json:"subscriptions"`
}

type EventSubscription struct {
	EventName   string                 `json:"event_name"`
	FilterRules map[string]interface{} `json:"filter_rules,omitempty"`
}

type CreateEndpointRequest struct {
	URL              string                 `form:"url" validate:"required,url"`
	Description      *string                `form:"description"`
	SubscribedEvents []string               `form:"subscribed_events"`
	Subscriptions    string                 `form:"subscriptions"`
	Headers          map[string]string      `form:"headers"`
	RateLimit        *model.RateLimitConfig `form:"rate_limit"`
}

type CreateEndpointResponse struct {
	Endpoint EndpointWithSubscriptions `json:"endpoint"`
}

type UpdateEndpointRequest struct {
	URL              string                 `form:"url" validate:"required,url"`
	Description      *string                `form:"description"`
	SubscribedEvents []string               `form:"subscribed_events"`
	Subscriptions    string                 `form:"subscriptions"`
	Headers          map[string]string      `form:"headers"`
	RateLimit        *model.RateLimitConfig `form:"rate_limit"`
	IsActive         *bool                  `form:"is_active"`
}

type UpdateEndpointResponse struct {
	Endpoint EndpointWithSubscriptions `json:"endpoint"`
}

type DeleteEndpointResponse struct {
	Deleted bool `json:"deleted"`
}

type ReplayDeliveryRequest struct {
	DeliveryIDs    []string `form:"delivery_ids"`
	StartDate      string   `form:"start_date"`
	EndDate        string   `form:"end_date"`
	Status         string   `form:"status"`
	EventName      string   `form:"event_name"`
	EndpointID     string   `form:"endpoint_id"`
	IdempotencyKey string   `form:"idempotency_key"`
}

type ReplayDeliveryResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	TaskID  string `json:"task_id,omitempty"`
}

type ReplayTaskCancelResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type ReplayTaskStatusResponse struct {
	TaskID         string `json:"task_id"`
	AppSlug        string `json:"app_slug"`
	Status         string `json:"status"`
	CreatedAt      string `json:"created_at,omitempty"`
	StartedAt      string `json:"started_at,omitempty"`
	CompletedAt    string `json:"completed_at,omitempty"`
	TotalCount     int64  `json:"total_count"`
	Processed      int64  `json:"processed"`
	ReplayedCount  int64  `json:"replayed_count"`
	FailedCount    int64  `json:"failed_count"`
	LastDeliveryID *int64 `json:"last_delivery_id,omitempty"`
}

type ReplayTaskListResponse struct {
	Data    []ReplayTaskStatusResponse `json:"data"`
	Limit   int                        `json:"limit"`
	Offset  int                        `json:"offset"`
	HasMore bool                       `json:"has_more"`
}

type StatsResponse struct {
	EndpointCount     int64 `json:"endpoint_count"`
	EventCount        int64 `json:"event_count"`
	PendingDeliveries int64 `json:"pending_deliveries"`
}

type TestEndpointRequest struct {
	EventName string `form:"event_name" validate:"required"`
	Payload   string `form:"payload" validate:"required"`
}

type TestEndpointResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type WebhookSettingsResponse struct {
	FailureNotificationEmails []string `json:"failure_notification_emails"`
}

type UpdateWebhookSettingsRequest struct {
	FailureNotificationEmails []string `form:"failure_notification_emails" validate:"omitempty,dive,email"`
}
