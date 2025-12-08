package notification

import (
	"strings"

	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
	"gorm.io/gorm"
)

func CalculateChannelCounts(userID uint64, session *model.Session) model.ChannelCounts {
	counts := model.ChannelCounts{}

	// User notifications (no organization or workspace)
	database.Connection.Model(&model.Notification{}).
		Where("user_id = ? AND is_read = false AND organization_id IS NULL AND workspace_id IS NULL", userID).
		Count(&counts.User)

	// Organization notifications
	userOrgIDs := getUserOrganizationIDs(userID)
	if len(userOrgIDs) > 0 {
		database.Connection.Model(&model.Notification{}).
			Where("user_id = ? AND is_read = false AND organization_id IN ?", userID, userOrgIDs).
			Count(&counts.Organization)
	}

	// Workspace notifications
	userWorkspaceIDs := getUserWorkspaceIDs(userID)
	if len(userWorkspaceIDs) > 0 {
		database.Connection.Model(&model.Notification{}).
			Where("user_id = ? AND is_read = false AND workspace_id IN ?", userID, userWorkspaceIDs).
			Count(&counts.Workspace)
	}

	// Current context notifications
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
		database.Connection.Model(&model.Notification{}).
			Where(whereClause, currentArgs...).
			Count(&counts.Current)
	}

	counts.Total = counts.User + counts.Organization + counts.Workspace + counts.Current
	return counts
}

func getUserOrganizationIDs(userID uint64) []uint64 {
	var orgIDs []uint64
	database.Connection.Model(&model.OrganizationMembership{}).
		Where("user_id = ?", userID).
		Pluck("organization_id", &orgIDs)
	return orgIDs
}

func getUserWorkspaceIDs(userID uint64) []uint64 {
	var wsIDs []uint64
	database.Connection.Model(&model.WorkspaceMembership{}).
		Where("user_id = ?", userID).
		Pluck("workspace_id", &wsIDs)
	return wsIDs
}

func ApplyChannelFilters(
	db *gorm.DB,
	req *model.NotificationListRequest,
	userID uint64,
	session *model.Session,
) *gorm.DB {
	db = db.Where("user_id = ?", userID)

	channels := req.Channels
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
			if len(req.OrganizationIDs) > 0 {
				placeholders := make([]string, len(req.OrganizationIDs))
				for i := range placeholders {
					placeholders[i] = "?"
				}
				channelConditions = append(channelConditions,
					"organization_id IN ("+strings.Join(placeholders, ",")+")")
				for _, orgID := range req.OrganizationIDs {
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
			if len(req.WorkspaceIDs) > 0 {
				placeholders := make([]string, len(req.WorkspaceIDs))
				for i := range placeholders {
					placeholders[i] = "?"
				}
				channelConditions = append(channelConditions,
					"workspace_id IN ("+strings.Join(placeholders, ",")+")")
				for _, wsID := range req.WorkspaceIDs {
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
		whereClause := "(" + strings.Join(channelConditions, " OR ") + ")"
		db = db.Where(whereClause, args...)
	}

	return db
}
