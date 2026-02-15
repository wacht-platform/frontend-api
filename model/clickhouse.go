package model

import (
	"time"
)

type WebhookEvent struct {
	DeploymentID     int64     `ch:"deployment_id" json:"deployment_id"`
	AppSlug          string    `ch:"app_slug" json:"app_slug"`
	EventName        string    `ch:"event_name" json:"event_name"`
	EventID          string    `ch:"event_id" json:"event_id"`
	PayloadSizeBytes int32     `ch:"payload_size_bytes" json:"payload_size_bytes"`
	FilterContext    *string   `ch:"filter_context" json:"filter_context,omitempty"`
	Timestamp        time.Time `ch:"timestamp" json:"timestamp"`
}

type WebhookDelivery struct {
	DeploymentID    int64     `ch:"deployment_id" json:"deployment_id"`
	DeliveryID      int64     `ch:"delivery_id" json:"delivery_id"`
	AppSlug         string    `ch:"app_slug" json:"app_slug"`
	EndpointID      int64     `ch:"endpoint_id" json:"endpoint_id"`
	EventName       string    `ch:"event_name" json:"event_name"`
	Status          string    `ch:"status" json:"status"`
	HTTPStatusCode  *int32    `ch:"http_status_code" json:"http_status_code,omitempty"`
	ResponseTimeMs  *int32    `ch:"response_time_ms" json:"response_time_ms,omitempty"`
	AttemptNumber   int32     `ch:"attempt_number" json:"attempt_number"`
	MaxAttempts     int32     `ch:"max_attempts" json:"max_attempts"`
	Payload         *string   `ch:"payload" json:"payload,omitempty"`
	ResponseBody    *string   `ch:"response_body" json:"response_body,omitempty"`
	ResponseHeaders *string   `ch:"response_headers" json:"response_headers,omitempty"`
	Timestamp       time.Time `ch:"timestamp" json:"timestamp"`
}

type WebhookDeliveryStatsRow struct {
	TotalDeliveries      uint64   `ch:"total_deliveries" json:"total_deliveries"`
	TotalEvents          uint64   `ch:"total_events" json:"total_events"`
	SuccessfulDeliveries uint64   `ch:"successful_deliveries" json:"successful_deliveries"`
	FailedDeliveries     uint64   `ch:"failed_deliveries" json:"failed_deliveries"`
	FilteredDeliveries   uint64   `ch:"filtered_deliveries" json:"filtered_deliveries"`
	AvgResponseTimeMs    *float64 `ch:"avg_response_time_ms" json:"avg_response_time_ms,omitempty"`
	P50ResponseTimeMs    *float64 `ch:"p50_response_time_ms" json:"p50_response_time_ms,omitempty"`
	P95ResponseTimeMs    *float64 `ch:"p95_response_time_ms" json:"p95_response_time_ms,omitempty"`
	P99ResponseTimeMs    *float64 `ch:"p99_response_time_ms" json:"p99_response_time_ms,omitempty"`
	AvgPayloadSize       *float64 `ch:"avg_payload_size" json:"avg_payload_size,omitempty"`
}

type WebhookDeliveryTimeseriesRow struct {
	Bucket               time.Time `ch:"bucket" json:"bucket"`
	TotalDeliveries      int64     `ch:"total_deliveries" json:"total_deliveries"`
	SuccessfulDeliveries int64     `ch:"successful_deliveries" json:"successful_deliveries"`
	FailedDeliveries     int64     `ch:"failed_deliveries" json:"failed_deliveries"`
	FilteredDeliveries   int64     `ch:"filtered_deliveries" json:"filtered_deliveries"`
	AvgResponseTimeMs    *float64  `ch:"avg_response_time_ms" json:"avg_response_time_ms,omitempty"`
}

type WebhookEventTimeseriesRow struct {
	Bucket      time.Time `ch:"bucket" json:"bucket"`
	TotalEvents int64     `ch:"total_events" json:"total_events"`
}

type ApiAuditLog struct {
	RequestID     string    `ch:"request_id" json:"request_id"`
	DeploymentID  int64     `ch:"deployment_id" json:"deployment_id"`
	AppSlug       string    `ch:"app_slug" json:"app_slug"`
	KeyID         int64     `ch:"key_id" json:"key_id"`
	KeyName       string    `ch:"key_name" json:"key_name"`
	Outcome       string    `ch:"outcome" json:"outcome"`
	BlockedByRule *string   `ch:"blocked_by_rule" json:"blocked_by_rule,omitempty"`
	ClientIP      string    `ch:"client_ip" json:"client_ip"`
	Path          string    `ch:"path" json:"path"`
	UserAgent     string    `ch:"user_agent" json:"user_agent"`
	RateLimits    *string   `ch:"rate_limits" json:"rate_limits,omitempty"`
	Timestamp     time.Time `ch:"timestamp" json:"timestamp"`
}

type ApiAuditStatsRow struct {
	TotalRequests   uint64 `ch:"total_requests" json:"total_requests"`
	AllowedRequests uint64 `ch:"allowed_requests" json:"allowed_requests"`
	BlockedRequests uint64 `ch:"blocked_requests" json:"blocked_requests"`
}

type ApiAuditTimeseriesRow struct {
	Bucket          time.Time `ch:"bucket" json:"bucket"`
	TotalRequests   int64     `ch:"total_requests" json:"total_requests"`
	AllowedRequests int64     `ch:"allowed_requests" json:"allowed_requests"`
	BlockedRequests int64     `ch:"blocked_requests" json:"blocked_requests"`
}
