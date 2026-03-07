package notification

import (
	"strings"
	"time"

	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/model"
	"gorm.io/gorm"
)

func normalizeChannels(req *model.NotificationListRequest) []string {
	if len(req.Channels) > 0 {
		out := make([]string, 0, len(req.Channels))
		for _, ch := range req.Channels {
			ch = strings.ToLower(strings.TrimSpace(ch))
			if ch != "" {
				out = append(out, ch)
			}
		}
		if len(out) > 0 {
			return out
		}
	}

	scope := strings.ToLower(strings.TrimSpace(req.Scope))
	switch scope {
	case "user":
		return []string{"user"}
	case "organization":
		return []string{"organization"}
	case "workspace":
		return []string{"workspace"}
	case "current":
		return []string{"current"}
	case "all":
		return []string{"user", "organization", "workspace"}
	}

	derived := make([]string, 0, 2)
	if len(req.OrganizationIDs) > 0 {
		derived = append(derived, "organization")
	}
	if len(req.WorkspaceIDs) > 0 {
		derived = append(derived, "workspace")
	}
	if len(derived) > 0 {
		return derived
	}
	return []string{"user"}
}

func GetScopeUnreadCount(
	userID uint64,
	session *model.Session,
	req *model.NotificationListRequest,
) int64 {
	db := database.Connection.Model(&model.Notification{}).
		Where("user_id = ? AND is_read = false AND (expires_at IS NULL OR expires_at > ?)", userID, time.Now())

	if req.IsArchived != nil {
		db = db.Where("is_archived = ?", *req.IsArchived)
	} else {
		db = db.Where("is_archived = false")
	}

	db = ApplyScopeFilters(db, req, userID, session)

	var count int64
	db.Limit(10).Count(&count)

	return count
}

func ApplyScopeFilters(
	db *gorm.DB,
	req *model.NotificationListRequest,
	userID uint64,
	session *model.Session,
) *gorm.DB {
	db = db.Where("user_id = ?", userID)
	channels := normalizeChannels(req)
	var clauses []string
	var args []interface{}

	for _, channel := range channels {
		switch channel {
		case "user":
			clauses = append(clauses, "(organization_id IS NULL AND workspace_id IS NULL)")
		case "organization":
			if len(req.OrganizationIDs) > 0 {
				clauses = append(clauses, "organization_id IN ?")
				args = append(args, req.OrganizationIDs)
			} else {
				clauses = append(clauses, "organization_id IS NOT NULL")
			}
		case "workspace":
			if len(req.WorkspaceIDs) > 0 {
				clauses = append(clauses, "workspace_id IN ?")
				args = append(args, req.WorkspaceIDs)
			} else {
				clauses = append(clauses, "workspace_id IS NOT NULL")
			}
		case "current":
			if session.ActiveSignin != nil {
				if m := session.ActiveSignin.ActiveWorkspaceMembership; m != nil {
					clauses = append(clauses, "workspace_id = ?")
					args = append(args, m.WorkspaceID)
				}
				if m := session.ActiveSignin.ActiveOrganizationMembership; m != nil {
					clauses = append(clauses, "(organization_id = ? AND workspace_id IS NULL)")
					args = append(args, m.OrganizationID)
				}
			}
			clauses = append(clauses, "(organization_id IS NULL AND workspace_id IS NULL)")
		}
	}

	if len(clauses) > 0 {
		db = db.Where("("+strings.Join(clauses, " OR ")+")", args...)
	}
	return db
}
