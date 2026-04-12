package notification

import (
	"log"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/model"
	"gorm.io/gorm"
)

func List(c fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	deployment := handler.GetDeployment(c)

	var req model.NotificationListRequest
	if err := c.Bind().Query(&req); err != nil {
		return handler.SendBadRequest(c, nil, "Invalid query parameters")
	}
	req.SetDefaults()

	var notifications []model.Notification

	db := database.Connection.Model(&model.Notification{}).
		Where("deployment_id = ?", deployment.ID)

	db = ApplyScopeFilters(db, &req, *session.ActiveSignin.UserID, session)
	db = req.ApplyFilters(db)

	if req.Cursor != nil {
		db = db.Where("id < ?", *req.Cursor)
	}

	// Fetch limit + 1 to determine hasMore
	if err := db.Order("created_at DESC, id DESC").
		Limit(req.Limit + 1).
		Find(&notifications).Error; err != nil {
		log.Printf("Failed to fetch notifications: %v", err)
		return handler.SendInternalServerError(c, nil, "Failed to fetch notifications")
	}

	hasMore := false
	if len(notifications) > req.Limit {
		hasMore = true
		notifications = notifications[:req.Limit]
	}

	response := model.NotificationListResponse{
		Notifications: notifications,
		HasMore:       hasMore,
	}

	return handler.SendSuccess(c, response)
}

func GetScopeUnread(c fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	var req model.NotificationListRequest
	if err := c.Bind().Query(&req); err != nil {
		return handler.SendBadRequest(c, nil, "Invalid query parameters")
	}

	count := GetScopeUnreadCount(*session.ActiveSignin.UserID, session, &req)

	return handler.SendSuccess(c, model.ScopeUnreadResponse{
		Count: count,
	})
}

func MarkAsRead(c fiber.Ctx) error {
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

func MarkAsUnread(c fiber.Ctx) error {
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

func MarkAllAsRead(c fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	deployment := handler.GetDeployment(c)

	var req model.NotificationListRequest
	if err := c.Bind().Query(&req); err != nil {
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

func ArchiveAllRead(c fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	deployment := handler.GetDeployment(c)

	var req model.NotificationListRequest
	if err := c.Bind().Query(&req); err != nil {
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

func Archive(c fiber.Ctx) error {
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

func Star(c fiber.Ctx) error {
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
