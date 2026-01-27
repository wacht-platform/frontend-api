package notification

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"gorm.io/gorm"
)

func List(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	deployment := handler.GetDeployment(c)

	var req model.NotificationListRequest
	if err := c.QueryParser(&req); err != nil {
		return handler.SendBadRequest(c, nil, "Invalid query parameters")
	}
	req.SetDefaults()

	type notificationResult struct {
		model.Notification
		FullCount    int64 `gorm:"column:full_count"`
		UnreadCapped int64 `gorm:"column:unread_capped"`
	}

	var results []notificationResult

	filterSQL := database.Connection.ToSQL(func(tx *gorm.DB) *gorm.DB {
		q := tx.Model(&model.Notification{}).
			Where("deployment_id = ?", deployment.ID)

		q = ApplyScopeFilters(q, &req, *session.ActiveSignin.UserID, session)
		q = req.ApplyFilters(q)

		return q.Find(&[]model.Notification{})
	})

	cteQuery := fmt.Sprintf(`
		WITH filtered AS (
			%s
		),
		counts AS (
			SELECT 
				(SELECT COUNT(*) FROM filtered) as full_count,
				(SELECT COUNT(*) FROM (SELECT 1 FROM filtered WHERE is_read = false LIMIT 10) AS u) as unread_capped
		),
		paginated AS (
			SELECT * FROM filtered ORDER BY created_at DESC LIMIT ? OFFSET ?
		)
		SELECT p.*, c.full_count, c.unread_capped
		FROM counts c
		LEFT JOIN paginated p ON true`, filterSQL)

	if err := database.Connection.Raw(cteQuery, req.Limit, req.Offset).Scan(&results).Error; err != nil {
		log.Printf("Failed optimized notification fetch: %v", err)
		return handler.SendInternalServerError(c, nil, "Failed to fetch notifications")
	}

	var total int64
	var unreadCount int64
	notifications := make([]model.Notification, 0)

	if len(results) > 0 {
		total = results[0].FullCount
		unreadCount = results[0].UnreadCapped

		for _, r := range results {
			if r.ID != 0 {
				notifications = append(notifications, r.Notification)
			}
		}
	}

	response := model.NotificationListResponse{
		Notifications: notifications,
		Total:         total,
		UnreadCount:   unreadCount,
		HasMore:       int64(req.Offset+req.Limit) < total,
	}

	return handler.SendSuccess(c, response)
}

func GetScopeUnread(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	var req model.NotificationListRequest
	if err := c.QueryParser(&req); err != nil {
		return handler.SendBadRequest(c, nil, "Invalid query parameters")
	}

	count := GetScopeUnreadCount(*session.ActiveSignin.UserID, session, &req)

	return handler.SendSuccess(c, model.ScopeUnreadResponse{
		Count: count,
	})
}

func MarkAsRead(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	deployment := handler.GetDeployment(c)

	notificationID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid notification ID")
	}

	var notification model.Notification
	result := database.Connection.Model(&model.Notification{}).
		Where("id = ?", notificationID).
		Where("user_id = ?", session.ActiveSignin.UserID).
		Where("deployment_id = ?", deployment.ID).
		First(&notification)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return handler.SendNotFound(c, nil, "Notification not found")
		}
		log.Printf("Failed to find notification: %v", result.Error)
		return handler.SendInternalServerError(c, nil, "Failed to find notification")
	}

	notification.MarkAsRead()

	if err := database.Connection.Save(&notification).Error; err != nil {
		log.Printf("Failed to update notification: %v", err)
		return handler.SendInternalServerError(c, nil, "Failed to update notification")
	}

	return handler.SendSuccess(c, fiber.Map{
		"message": "Notification marked as read",
		"success": true,
	})
}

func MarkAsUnread(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	deployment := handler.GetDeployment(c)

	notificationID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid notification ID")
	}

	var notification model.Notification
	result := database.Connection.Model(&model.Notification{}).
		Where("id = ?", notificationID).
		Where("user_id = ?", session.ActiveSignin.UserID).
		Where("deployment_id = ?", deployment.ID).
		First(&notification)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return handler.SendNotFound(c, nil, "Notification not found")
		}
		log.Printf("Failed to find notification: %v", result.Error)
		return handler.SendInternalServerError(c, nil, "Failed to find notification")
	}

	notification.MarkAsUnread()

	if err := database.Connection.Save(&notification).Error; err != nil {
		log.Printf("Failed to update notification: %v", err)
		return handler.SendInternalServerError(c, nil, "Failed to update notification")
	}

	return handler.SendSuccess(c, fiber.Map{
		"message": "Notification marked as unread",
		"success": true,
	})
}

func MarkAllAsRead(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	deployment := handler.GetDeployment(c)

	var req model.NotificationListRequest
	if err := c.QueryParser(&req); err != nil {
		return handler.SendBadRequest(c, nil, "Invalid query parameters")
	}

	db := database.Connection.Model(&model.Notification{}).
		Where("user_id = ?", session.ActiveSignin.UserID).
		Where("deployment_id = ?", deployment.ID)

	db = ApplyScopeFilters(db, &req, *session.ActiveSignin.UserID, session)
	db = req.ApplyFilters(db)

	result := db.Where("is_read = false").
		Updates(map[string]interface{}{
			"is_read":    true,
			"read_at":    time.Now(),
			"updated_at": time.Now(),
		})

	if result.Error != nil {
		log.Printf("Failed to mark all notifications as read: %v", result.Error)
		return handler.SendInternalServerError(c, nil, "Failed to mark all notifications as read")
	}

	return handler.SendSuccess(c, model.BulkUpdateResponse{
		Affected: result.RowsAffected,
	})
}

func ArchiveAllRead(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	deployment := handler.GetDeployment(c)

	var req model.NotificationListRequest
	if err := c.QueryParser(&req); err != nil {
		return handler.SendBadRequest(c, nil, "Invalid query parameters")
	}

	db := database.Connection.Model(&model.Notification{}).
		Where("user_id = ?", session.ActiveSignin.UserID).
		Where("deployment_id = ?", deployment.ID)

	db = ApplyScopeFilters(db, &req, *session.ActiveSignin.UserID, session)
	db = req.ApplyFilters(db)

	result := db.Where("is_read = true").
		Where("is_archived = false").
		Updates(map[string]interface{}{
			"is_archived": true,
			"archived_at": time.Now(),
			"updated_at":  time.Now(),
		})

	if result.Error != nil {
		log.Printf("Failed to archive all read notifications: %v", result.Error)
		return handler.SendInternalServerError(c, nil, "Failed to archive all read notifications")
	}

	return handler.SendSuccess(c, model.BulkUpdateResponse{
		Affected: result.RowsAffected,
	})
}

// Archive archives a notification (soft delete)
func Archive(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	deployment := handler.GetDeployment(c)

	notificationID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid notification ID")
	}

	var notification model.Notification
	result := database.Connection.Model(&model.Notification{}).
		Where("id = ?", notificationID).
		Where("user_id = ?", session.ActiveSignin.UserID).
		Where("deployment_id = ?", deployment.ID).
		First(&notification)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return handler.SendNotFound(c, nil, "Notification not found")
		}
		log.Printf("Failed to find notification: %v", result.Error)
		return handler.SendInternalServerError(c, nil, "Failed to find notification")
	}

	notification.ToggleArchive()

	if err := database.Connection.Save(&notification).Error; err != nil {
		log.Printf("Failed to archive notification: %v", err)
		return handler.SendInternalServerError(c, nil, "Failed to update notification archive status")
	}

	return handler.SendSuccess(c, fiber.Map{
		"message":     "Notification archive status updated",
		"is_archived": notification.IsArchived,
		"success":     true,
	})
}

func Star(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	deployment := handler.GetDeployment(c)

	notificationID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid notification ID")
	}

	var notification model.Notification
	result := database.Connection.Model(&model.Notification{}).
		Where("id = ?", notificationID).
		Where("user_id = ?", session.ActiveSignin.UserID).
		Where("deployment_id = ?", deployment.ID).
		First(&notification)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return handler.SendNotFound(c, nil, "Notification not found")
		}
		log.Printf("Failed to find notification: %v", result.Error)
		return handler.SendInternalServerError(c, nil, "Failed to find notification")
	}

	notification.ToggleStar()

	if err := database.Connection.Save(&notification).Error; err != nil {
		log.Printf("Failed to update notification star status: %v", err)
		return handler.SendInternalServerError(c, nil, "Failed to update notification")
	}

	return handler.SendSuccess(c, fiber.Map{
		"message":    "Notification star status updated",
		"is_starred": notification.IsStarred,
		"success":    true,
	})
}

func Get(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	deployment := handler.GetDeployment(c)

	notificationID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid notification ID")
	}

	var notification model.Notification
	result := database.Connection.Model(&model.Notification{}).
		Where("id = ?", notificationID).
		Where("user_id = ?", session.ActiveSignin.UserID).
		Where("deployment_id = ?", deployment.ID).
		First(&notification)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return handler.SendNotFound(c, nil, "Notification not found")
		}
		log.Printf("Failed to find notification: %v", result.Error)
		return handler.SendInternalServerError(c, nil, "Failed to find notification")
	}

	return handler.SendSuccess(c, notification)
}
