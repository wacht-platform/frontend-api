package model

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

type NotificationSeverity string

const (
	SeverityInfo    NotificationSeverity = "info"
	SeveritySuccess NotificationSeverity = "success"
	SeverityWarning NotificationSeverity = "warning"
	SeverityError   NotificationSeverity = "error"
)

type CTA struct {
	Label   string `json:"label"`
	Payload any    `json:"payload"`
}

type Notification struct {
	ID             uint64               `json:"id,string"                 gorm:"primaryKey"`
	DeploymentID   uint64               `json:"deployment_id,string"      gorm:"not null;index"`
	UserID         uint64               `json:"user_id,string"            gorm:"not null;index"`
	OrganizationID *uint64              `json:"organization_id,string,omitempty" gorm:"index"`
	WorkspaceID    *uint64              `json:"workspace_id,string,omitempty"    gorm:"index"`
	Title          string               `json:"title" gorm:"not null"`
	Body           string               `json:"body"  gorm:"not null"`
	CTAs           []CTA                `json:"ctas" gorm:"column:ctas;type:jsonb;serializer:json"`
	Severity       NotificationSeverity `json:"severity"              gorm:"default:'info'"`
	IsRead         bool                 `json:"is_read"               gorm:"default:false;index"`
	ReadAt         *time.Time           `json:"read_at,omitempty"`
	IsArchived     bool                 `json:"is_archived"           gorm:"default:false;index"`
	ArchivedAt     *time.Time           `json:"archived_at,omitempty"`
	Metadata       json.RawMessage      `json:"metadata,omitempty" gorm:"type:jsonb"`
	CreatedAt      time.Time            `json:"created_at"           gorm:"not null;index"`
	UpdatedAt      time.Time            `json:"updated_at"           gorm:"not null"`
	ExpiresAt      *time.Time           `json:"expires_at,omitempty" gorm:"index"`
	IsStarred      bool                 `json:"is_starred"           gorm:"default:false;index"`
}

func (Notification) TableName() string {
	return "notifications"
}

type NotificationListRequest struct {
	Limit      int                   `json:"limit"                 form:"limit"            query:"limit"            validate:"min=1,max=100"`
	Offset     int                   `json:"offset"                form:"offset"           query:"offset"           validate:"min=0"`
	Scope      string                `json:"scope"                 form:"scope"            query:"scope"`
	IsRead     *bool                 `json:"is_read,omitempty"     form:"is_read"          query:"is_read"`
	IsStarred  *bool                 `json:"is_starred,omitempty"  form:"is_starred"       query:"is_starred"`
	IsArchived *bool                 `json:"is_archived,omitempty" form:"is_archived"      query:"is_archived"`
	Severity   *NotificationSeverity `json:"severity,omitempty"    form:"severity"         query:"severity"`
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
}

type ScopeUnreadResponse struct {
	Count int64 `json:"count"`
}

type BulkUpdateResponse struct {
	Affected int64 `json:"affected"`
}

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

func (s NotificationSeverity) Value() (driver.Value, error) {
	return string(s), nil
}

func (r *NotificationListRequest) ApplyFilters(db *gorm.DB) *gorm.DB {
	if r.Severity != nil {
		db = db.Where("severity = ?", *r.Severity)
	}
	if r.IsRead != nil {
		db = db.Where("is_read = ?", *r.IsRead)
	}
	if r.IsStarred != nil {
		db = db.Where("is_starred = ?", *r.IsStarred)
	}

	if r.IsArchived != nil {
		db = db.Where("is_archived = ?", *r.IsArchived)
	} else {
		// Default to not showing archived notifications
		db = db.Where("is_archived = false")
	}
	db = db.Where("(expires_at IS NULL OR expires_at > ?)", time.Now())

	return db
}

func (r *NotificationListRequest) SetDefaults() {
	if r.Limit == 0 {
		r.Limit = 20
	}
	if r.Limit > 100 {
		r.Limit = 100
	}
}

func (n *Notification) MarkAsRead() {
	n.IsRead = true
	now := time.Now()
	n.ReadAt = &now
	n.UpdatedAt = now
}

func (n *Notification) MarkAsUnread() {
	n.IsRead = false
	n.ReadAt = nil
	n.UpdatedAt = time.Now()
}

func (n *Notification) ToggleArchive() {
	n.IsArchived = !n.IsArchived
	now := time.Now()
	if n.IsArchived {
		n.ArchivedAt = &now
		n.IsRead = true
		n.ReadAt = &now
	} else {
		n.ArchivedAt = nil
	}
	n.UpdatedAt = now
}

func (n *Notification) ToggleStar() {
	n.IsStarred = !n.IsStarred
	n.UpdatedAt = time.Now()
}
