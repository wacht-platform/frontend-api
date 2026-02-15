package model

import (
	"time"

	"gorm.io/datatypes"
)

type WebhookApp struct {
	DeploymentID     uint64    `gorm:"column:deployment_id;primarykey" json:"deployment_id,string"`
	AppSlug          string    `gorm:"column:app_slug;primarykey" json:"app_slug"`
	Name             string    `gorm:"column:name" json:"name"`
	Description      *string   `gorm:"column:description" json:"description,omitempty"`
	SigningSecret    string    `gorm:"column:signing_secret" json:"signing_secret"`
	EventCatalogSlug *string   `gorm:"column:event_catalog_slug" json:"event_catalog_slug,omitempty"`
	IsActive         bool      `gorm:"column:is_active" json:"is_active"`
	CreatedAt        time.Time `gorm:"column:created_at" json:"created_at"`
	UpdatedAt        time.Time `gorm:"column:updated_at" json:"updated_at"`
}

func (WebhookApp) TableName() string {
	return "webhook_apps"
}

type WebhookEventCatalog struct {
	DeploymentID uint64    `gorm:"column:deployment_id;primarykey" json:"deployment_id,string"`
	Slug         string    `gorm:"column:slug;primarykey" json:"slug"`
	Name         string    `gorm:"column:name" json:"name"`
	Description  *string   `gorm:"column:description" json:"description,omitempty"`
	Events       []byte    `gorm:"column:events;type:jsonb" json:"events"`
	CreatedAt    time.Time `gorm:"column:created_at" json:"created_at"`
	UpdatedAt    time.Time `gorm:"column:updated_at" json:"updated_at"`
}

func (WebhookEventCatalog) TableName() string {
	return "webhook_event_catalogs"
}

type RateLimitConfig struct {
	DurationMs  int64 `json:"duration_ms"  form:"duration_ms"`
	MaxRequests int32 `json:"max_requests" form:"max_requests"`
}

type WebhookEndpoint struct {
	ID             uint64             `gorm:"column:id;primarykey" json:"id,string"`
	DeploymentID   uint64             `gorm:"column:deployment_id" json:"deployment_id,string"`
	AppSlug        string             `gorm:"column:app_slug" json:"app_slug"`
	URL            string             `gorm:"column:url" json:"url"`
	Description    *string            `gorm:"column:description" json:"description,omitempty"`
	Headers        datatypes.JSONMap  `gorm:"column:headers;type:jsonb" json:"headers,omitempty"`
	IsActive       bool               `gorm:"column:is_active" json:"is_active"`
	MaxRetries     int32              `gorm:"column:max_retries" json:"max_retries"`
	TimeoutSeconds int32              `gorm:"column:timeout_seconds" json:"timeout_seconds"`
	FailureCount   int32              `gorm:"column:failure_count" json:"failure_count"`
	LastFailureAt  *time.Time         `gorm:"column:last_failure_at" json:"last_failure_at,omitempty"`
	AutoDisabled   bool               `gorm:"column:auto_disabled" json:"auto_disabled"`
	AutoDisabledAt *time.Time         `gorm:"column:auto_disabled_at" json:"auto_disabled_at,omitempty"`
	RateLimit      *datatypes.JSONMap `gorm:"column:rate_limit_config;type:jsonb" json:"rate_limit_config,omitempty"`
	CreatedAt      time.Time          `gorm:"column:created_at" json:"created_at"`
	UpdatedAt      time.Time          `gorm:"column:updated_at" json:"updated_at"`
}

func (WebhookEndpoint) TableName() string {
	return "webhook_endpoints"
}

type WebhookEndpointSubscription struct {
	EndpointID   uint64            `gorm:"column:endpoint_id;primarykey" json:"endpoint_id,string"`
	DeploymentID uint64            `gorm:"column:deployment_id;primarykey" json:"deployment_id,string"`
	AppSlug      string            `gorm:"column:app_slug;primarykey" json:"app_slug"`
	EventName    string            `gorm:"column:event_name;primarykey" json:"event_name"`
	FilterRules  datatypes.JSONMap `gorm:"column:filter_rules;type:jsonb" json:"filter_rules,omitempty"`
	CreatedAt    time.Time         `gorm:"column:created_at" json:"created_at"`
}

func (WebhookEndpointSubscription) TableName() string {
	return "webhook_endpoint_subscriptions"
}

type ActiveWebhookDelivery struct {
	ID               uint64         `gorm:"column:id;primarykey" json:"id,string"`
	EndpointID       uint64         `gorm:"column:endpoint_id" json:"endpoint_id,string"`
	DeploymentID     uint64         `gorm:"column:deployment_id" json:"deployment_id,string"`
	AppSlug          string         `gorm:"column:app_slug" json:"app_slug"`
	EventName        string         `gorm:"column:event_name" json:"event_name"`
	Payload          map[string]any `gorm:"column:payload;type:jsonb" json:"payload"`
	FilterRules      datatypes.JSONMap `gorm:"column:filter_rules;type:jsonb" json:"filter_rules,omitempty"`
	PayloadSizeBytes int32          `gorm:"column:payload_size_bytes" json:"payload_size_bytes"`
	WebhookID        string         `gorm:"column:webhook_id" json:"webhook_id"`
	WebhookTimestamp int64          `gorm:"column:webhook_timestamp" json:"webhook_timestamp"`
	Signature        *string        `gorm:"column:signature" json:"signature,omitempty"`
	Attempts         int32          `gorm:"column:attempts" json:"attempts"`
	MaxAttempts      int32          `gorm:"column:max_attempts" json:"max_attempts"`
	NextRetryAt      time.Time      `gorm:"column:next_retry_at" json:"next_retry_at"`
	CreatedAt        time.Time      `gorm:"column:created_at" json:"created_at"`
}

func (ActiveWebhookDelivery) TableName() string {
	return "active_webhook_deliveries"
}
