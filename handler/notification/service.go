package notification

import (
	"strings"
	"time"

	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
	"gorm.io/gorm"
)

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

	switch req.Scope {
	case "user":
		db = db.Where("organization_id IS NULL AND workspace_id IS NULL")
	case "current":
		var currentConditions []string
		var args []interface{}
		if session.ActiveSignin.ActiveOrganizationMembership != nil {
			currentConditions = append(currentConditions, "organization_id = ?")
			args = append(args, session.ActiveSignin.ActiveOrganizationMembership.OrganizationID)
		}
		if session.ActiveSignin.ActiveWorkspaceMembership != nil {
			currentConditions = append(currentConditions, "workspace_id = ?")
			args = append(args, session.ActiveSignin.ActiveWorkspaceMembership.WorkspaceID)
		}
		if len(currentConditions) > 0 {
			db = db.Where("("+strings.Join(currentConditions, " OR ")+")", args...)
		} else {
			db = db.Where("organization_id IS NULL AND workspace_id IS NULL")
		}
	case "all":
	default:
	}

	return db
}
