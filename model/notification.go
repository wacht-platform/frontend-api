package model

import (
	"database/sql/driver"
	"encoding/json"
	"strings"
	"time"

	"github.com/ilabs/wacht-fe/database"
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
	ID             uint64  `json:"id" gorm:"primaryKey"`
	DeploymentID   uint64  `json:"deployment_id" gorm:"not null;index"`
	UserID         uint64  `json:"user_id" gorm:"not null;index"`
	OrganizationID *uint64 `json:"organization_id,omitempty" gorm:"index"`
	WorkspaceID    *uint64 `json:"workspace_id,omitempty" gorm:"index"`

	// Content
	Title string `json:"title" gorm:"not null"`
	Body  string `json:"body" gorm:"not null"`

	// Action
	ActionURL   *string `json:"action_url,omitempty"`
	ActionLabel *string `json:"action_label,omitempty"`

	// Status
	Severity   NotificationSeverity `json:"severity" gorm:"default:'info'"`
	IsRead     bool                 `json:"is_read" gorm:"default:false;index"`
	ReadAt     *time.Time           `json:"read_at,omitempty"`
	IsArchived bool                 `json:"is_archived" gorm:"default:false;index"`
	ArchivedAt *time.Time           `json:"archived_at,omitempty"`

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

type NotificationListRequest struct {
	Limit           int                   `json:"limit" form:"limit" validate:"min=1,max=100"`
	Offset          int                   `json:"offset" form:"offset" validate:"min=0"`
	Channels        []string              `json:"channels" form:"channels"`
	OrganizationIDs []uint64              `json:"organization_ids" form:"organization_ids"`
	WorkspaceIDs    []uint64              `json:"workspace_ids" form:"workspace_ids"`
	IsRead          *bool                 `json:"is_read,omitempty" form:"is_read"`
	IsArchived      *bool                 `json:"is_archived,omitempty" form:"is_archived"`
	Severity        *NotificationSeverity `json:"severity,omitempty" form:"severity"`
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

func (r *NotificationListRequest) ApplyChannelFilters(db *gorm.DB, userID uint64, session *Session) *gorm.DB {
	db = db.Where("user_id = ?", userID)

	channels := r.Channels
	if len(channels) == 0 {
		channels = []string{"user"}
	}

	var channelConditions []string
	var args []interface{}

	for _, channel := range channels {
		switch channel {
		case "user":
			channelConditions = append(channelConditions, "(organization_id IS NULL AND workspace_id IS NULL)")

		case "organization":
			if len(r.OrganizationIDs) > 0 {
				placeholders := make([]string, len(r.OrganizationIDs))
				for i := range placeholders {
					placeholders[i] = "?"
				}
				channelConditions = append(channelConditions,
					"organization_id IN ("+strings.Join(placeholders, ",")+")")
				for _, orgID := range r.OrganizationIDs {
					args = append(args, orgID)
				}
			} else {
				userOrgIDs := getUserOrganizationIDs(userID)
				if len(userOrgIDs) > 0 {
					placeholders := make([]string, len(userOrgIDs))
					for i := range placeholders {
						placeholders[i] = "?"
					}
					channelConditions = append(channelConditions,
						"organization_id IN ("+strings.Join(placeholders, ",")+")")
					for _, orgID := range userOrgIDs {
						args = append(args, orgID)
					}
				}
			}

		case "workspace":
			if len(r.WorkspaceIDs) > 0 {
				placeholders := make([]string, len(r.WorkspaceIDs))
				for i := range placeholders {
					placeholders[i] = "?"
				}
				channelConditions = append(channelConditions,
					"workspace_id IN ("+strings.Join(placeholders, ",")+")")
				for _, wsID := range r.WorkspaceIDs {
					args = append(args, wsID)
				}
			} else {
				userWorkspaceIDs := getUserWorkspaceIDs(userID)
				if len(userWorkspaceIDs) > 0 {
					placeholders := make([]string, len(userWorkspaceIDs))
					for i := range placeholders {
						placeholders[i] = "?"
					}
					channelConditions = append(channelConditions,
						"workspace_id IN ("+strings.Join(placeholders, ",")+")")
					for _, wsID := range userWorkspaceIDs {
						args = append(args, wsID)
					}
				}
			}

		case "current":
			var currentConditions []string

			if session.ActiveSignin.ActiveOrganizationMembership != nil {
				currentConditions = append(currentConditions, "organization_id = ?")
				args = append(args, session.ActiveSignin.ActiveOrganizationMembership.OrganizationID)
			}

			if session.ActiveSignin.ActiveWorkspaceMembership != nil {
				currentConditions = append(currentConditions, "workspace_id = ?")
				args = append(args, session.ActiveSignin.ActiveWorkspaceMembership.WorkspaceID)
			}

			if len(currentConditions) > 0 {
				channelConditions = append(channelConditions, "("+strings.Join(currentConditions, " OR ")+")")
			}
		}
	}

	if len(channelConditions) > 0 {
		db = db.Where("("+strings.Join(channelConditions, " OR ")+")", args...)
	}

	return db
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

func getUserOrganizationIDs(userID uint64) []uint64 {
	var orgIDs []uint64
	database.Connection.Model(&OrganizationMembership{}).
		Where("user_id = ?", userID).
		Pluck("organization_id", &orgIDs)
	return orgIDs
}

func getUserWorkspaceIDs(userID uint64) []uint64 {
	var wsIDs []uint64
	database.Connection.Model(&WorkspaceMembership{}).
		Where("user_id = ?", userID).
		Pluck("workspace_id", &wsIDs)
	return wsIDs
}

func GetChannelCounts(userID uint64, session *Session) ChannelCounts {
	counts := ChannelCounts{}

	database.Connection.Model(&Notification{}).
		Where("user_id = ? AND is_read = false AND organization_id IS NULL AND workspace_id IS NULL", userID).
		Count(&counts.User)

	userOrgIDs := getUserOrganizationIDs(userID)
	if len(userOrgIDs) > 0 {
		database.Connection.Model(&Notification{}).
			Where("user_id = ? AND is_read = false AND organization_id IN ?", userID, userOrgIDs).
			Count(&counts.Organization)
	}

	userWorkspaceIDs := getUserWorkspaceIDs(userID)
	if len(userWorkspaceIDs) > 0 {
		database.Connection.Model(&Notification{}).
			Where("user_id = ? AND is_read = false AND workspace_id IN ?", userID, userWorkspaceIDs).
			Count(&counts.Workspace)
	}

	var currentConditions []string
	var currentArgs []interface{}
	currentArgs = append(currentArgs, userID)

	if session.ActiveSignin.ActiveOrganizationMembership != nil {
		currentConditions = append(currentConditions, "organization_id = ?")
		currentArgs = append(currentArgs, session.ActiveSignin.ActiveOrganizationMembership.OrganizationID)
	}

	if session.ActiveSignin.ActiveWorkspaceMembership != nil {
		currentConditions = append(currentConditions, "workspace_id = ?")
		currentArgs = append(currentArgs, session.ActiveSignin.ActiveWorkspaceMembership.WorkspaceID)
	}

	if len(currentConditions) > 0 {
		whereClause := "user_id = ? AND is_read = false AND (" + strings.Join(currentConditions, " OR ") + ")"
		database.Connection.Model(&Notification{}).
			Where(whereClause, currentArgs...).
			Count(&counts.Current)
	}

	counts.Total = counts.User + counts.Organization + counts.Workspace + counts.Current
	return counts
}
