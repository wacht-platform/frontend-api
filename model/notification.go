package model

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

// NotificationSeverity represents the severity level of a notification
type NotificationSeverity string

const (
	SeverityInfo    NotificationSeverity = "info"
	SeveritySuccess NotificationSeverity = "success"
	SeverityWarning NotificationSeverity = "warning"
	SeverityError   NotificationSeverity = "error"
)

// Notification represents a user notification
type Notification struct {
	ID             uint64          `json:"id" gorm:"primaryKey"`
	DeploymentID   uint64          `json:"deployment_id" gorm:"not null;index"`
	UserID         uint64          `json:"user_id" gorm:"not null;index"`
	OrganizationID *uint64         `json:"organization_id,omitempty" gorm:"index"`
	WorkspaceID    *uint64         `json:"workspace_id,omitempty" gorm:"index"`
	
	// Content
	Title  string `json:"title" gorm:"not null"`
	Body   string `json:"body" gorm:"not null"`
	
	// Action
	ActionURL   *string `json:"action_url,omitempty"`
	ActionLabel *string `json:"action_label,omitempty"`
	
	// Status
	Severity   NotificationSeverity `json:"severity" gorm:"default:'info'"`
	IsRead     bool                 `json:"is_read" gorm:"default:false;index"`
	ReadAt     *time.Time           `json:"read_at,omitempty"`
	IsArchived bool                 `json:"is_archived" gorm:"default:false;index"`
	ArchivedAt *time.Time           `json:"archived_at,omitempty"`
	
	// Grouping
	GroupID    *string `json:"group_id,omitempty" gorm:"index"`
	GroupCount int32   `json:"group_count" gorm:"default:1"`
	
	// Deduplication
	DedupeKey *string `json:"dedupe_key,omitempty" gorm:"index"`
	
	// Source
	Source   *string `json:"source,omitempty"`
	SourceID *string `json:"source_id,omitempty"`
	
	// Metadata
	Metadata json.RawMessage `json:"metadata,omitempty" gorm:"type:jsonb"`
	
	// Timestamps
	CreatedAt time.Time  `json:"created_at" gorm:"not null;index"`
	UpdatedAt time.Time  `json:"updated_at" gorm:"not null"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" gorm:"index"`
}

// TableName specifies the table name for GORM
func (Notification) TableName() string {
	return "notifications"
}

// NotificationListRequest represents request parameters for listing notifications
type NotificationListRequest struct {
	Limit      int                   `json:"limit" form:"limit" validate:"min=1,max=100"`
	Offset     int                   `json:"offset" form:"offset" validate:"min=0"`
	IsRead     *bool                 `json:"is_read,omitempty" form:"is_read"`
	IsArchived *bool                 `json:"is_archived,omitempty" form:"is_archived"`
	Severity   *NotificationSeverity `json:"severity,omitempty" form:"severity"`
	Source     *string               `json:"source,omitempty" form:"source"`
}

// NotificationListResponse represents the response for listing notifications
type NotificationListResponse struct {
	Notifications []Notification `json:"notifications"`
	Total         int64          `json:"total"`
	UnreadCount   int64          `json:"unread_count"`
	HasMore       bool           `json:"has_more"`
}

// UnreadCountResponse represents the response for unread count
type UnreadCountResponse struct {
	Count int64 `json:"count"`
}

// BulkUpdateResponse represents the response for bulk operations
type BulkUpdateResponse struct {
	Affected int64 `json:"affected"`
}

// Scan implements sql.Scanner interface for NotificationSeverity
func (s *NotificationSeverity) Scan(value interface{}) error {
	if value == nil {
		*s = SeverityInfo
		return nil
	}
	if sv, ok := value.(string); ok {
		*s = NotificationSeverity(sv)
		return nil
	}
	if bv, ok := value.([]byte); ok {
		*s = NotificationSeverity(bv)
		return nil
	}
	*s = SeverityInfo
	return nil
}

// Value implements driver.Valuer interface for NotificationSeverity
func (s NotificationSeverity) Value() (driver.Value, error) {
	return string(s), nil
}

// Helper functions for building queries

// ApplyFilters applies filters to a GORM query
func (r *NotificationListRequest) ApplyFilters(db *gorm.DB) *gorm.DB {
	if r.IsRead != nil {
		db = db.Where("is_read = ?", *r.IsRead)
	}
	if r.IsArchived != nil {
		db = db.Where("is_archived = ?", *r.IsArchived)
	} else {
		// By default, exclude archived notifications
		db = db.Where("is_archived = false")
	}
	if r.Severity != nil {
		db = db.Where("severity = ?", *r.Severity)
	}
	if r.Source != nil {
		db = db.Where("source = ?", *r.Source)
	}
	// Filter out expired notifications
	db = db.Where("(expires_at IS NULL OR expires_at > ?)", time.Now())
	
	return db
}

// SetDefaults sets default values for the request
func (r *NotificationListRequest) SetDefaults() {
	if r.Limit == 0 {
		r.Limit = 20
	}
	if r.Limit > 100 {
		r.Limit = 100
	}
}


// MarkAsRead marks the notification as read
func (n *Notification) MarkAsRead() {
	n.IsRead = true
	now := time.Now()
	n.ReadAt = &now
	n.UpdatedAt = now
}

// Archive archives the notification
func (n *Notification) Archive() {
	n.IsArchived = true
	now := time.Now()
	n.ArchivedAt = &now
	n.UpdatedAt = now
}