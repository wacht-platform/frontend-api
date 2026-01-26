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
	ID             uint64  `json:"id"                        gorm:"primaryKey"`
	DeploymentID   uint64  `json:"deployment_id"             gorm:"not null;index"`
	UserID         uint64  `json:"user_id"                   gorm:"not null;index"`
	OrganizationID *uint64 `json:"organization_id,omitempty" gorm:"index"`
	WorkspaceID    *uint64 `json:"workspace_id,omitempty"    gorm:"index"`

	// Content
	Title string `json:"title" gorm:"not null"`
	Body  string `json:"body"  gorm:"not null"`

	// Interactive
	CTAs json.RawMessage `json:"ctas,omitempty" gorm:"type:jsonb"` // Array of {label: string, payload: any}

	// Status
	Severity   NotificationSeverity `json:"severity"              gorm:"default:'info'"`
	IsRead     bool                 `json:"is_read"               gorm:"default:false;index"`
	ReadAt     *time.Time           `json:"read_at,omitempty"`
	IsArchived bool                 `json:"is_archived"           gorm:"default:false;index"`
	ArchivedAt *time.Time           `json:"archived_at,omitempty"`

	// Metadata
	Metadata json.RawMessage `json:"metadata,omitempty" gorm:"type:jsonb"`

	// Timestamps
	CreatedAt time.Time  `json:"created_at"           gorm:"not null;index"`
	UpdatedAt time.Time  `json:"updated_at"           gorm:"not null"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" gorm:"index"`
}

// TableName specifies the table name for GORM
func (Notification) TableName() string {
	return "notifications"
}

type NotificationListRequest struct {
	Limit           int                   `json:"limit"                 form:"limit"            validate:"min=1,max=100"`
	Offset          int                   `json:"offset"                form:"offset"           validate:"min=0"`
	Channels        []string              `json:"channels"              form:"channels"`
	OrganizationIDs []uint64              `json:"organization_ids"      form:"organization_ids"`
	WorkspaceIDs    []uint64              `json:"workspace_ids"         form:"workspace_ids"`
	IsRead          *bool                 `json:"is_read,omitempty"     form:"is_read"`
	IsArchived      *bool                 `json:"is_archived,omitempty" form:"is_archived"`
	Severity        *NotificationSeverity `json:"severity,omitempty"    form:"severity"`
}

type ChannelCounts struct {
	User         int64 `json:"user"`
	Organization int64 `json:"organization"`
	Workspace    int64 `json:"workspace"`
	Current      int64 `json:"current"`
	Total        int64 `json:"total"`
}

type NotificationListResponse struct {
	Notifications []Notification `json:"notifications"`
	Total         int64          `json:"total"`
	UnreadCount   int64          `json:"unread_count"`
	HasMore       bool           `json:"has_more"`
	Channels      []string       `json:"channels"`
	UnreadCounts  ChannelCounts  `json:"unread_counts"`
}

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
