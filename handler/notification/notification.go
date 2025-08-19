package notification

import (
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

	// Parse query parameters
	var req model.NotificationListRequest
	if err := c.QueryParser(&req); err != nil {
		return handler.SendBadRequest(c, nil, "Invalid query parameters")
	}
	req.SetDefaults()

	baseQuery := database.Connection.Model(&model.Notification{}).
		Where("deployment_id = ?", deployment.ID)

	baseQuery = req.ApplyChannelFilters(baseQuery, *session.ActiveSignin.UserID, session)

	baseQuery = req.ApplyFilters(baseQuery)

	var total int64
	if err := baseQuery.Count(&total).Error; err != nil {
		log.Printf("Failed to count notifications: %v", err)
		return handler.SendInternalServerError(c, nil, "Failed to count notifications")
	}

	// Get unread count
	var unreadCount int64
	if err := database.Connection.Model(&model.Notification{}).
		Where("user_id = ?", session.ActiveSignin.UserID).
		Where("deployment_id = ?", deployment.ID).
		Where("is_read = false").
		Where("is_archived = false").
		Where("(expires_at IS NULL OR expires_at > ?)", time.Now()).
		Count(&unreadCount).Error; err != nil {
		log.Printf("Failed to count unread notifications: %v", err)
		return handler.SendInternalServerError(c, nil, "Failed to count unread notifications")
	}

	// Get notifications with pagination
	var notifications []model.Notification
	if err := baseQuery.
		Order("created_at DESC").
		Limit(req.Limit).
		Offset(req.Offset).
		Find(&notifications).Error; err != nil {
		log.Printf("Failed to fetch notifications: %v", err)
		return handler.SendInternalServerError(c, nil, "Failed to fetch notifications")
	}

	// If no notifications found, return empty array instead of null
	if notifications == nil {
		notifications = []model.Notification{}
	}

	channelCounts := model.GetChannelCounts(*session.ActiveSignin.UserID, session)

	channels := req.Channels
	if len(channels) == 0 {
		channels = []string{"user"}
	}

	response := model.NotificationListResponse{
		Notifications: notifications,
		Total:         total,
		UnreadCount:   channelCounts.Total,
		HasMore:       int64(req.Offset+req.Limit) < total,
		Channels:      channels,
		UnreadCounts:  channelCounts,
	}

	return handler.SendSuccess(c, response)
}

// GetUnreadCount returns the count of unread notifications
func GetUnreadCount(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	deployment := handler.GetDeployment(c)

	var count int64
	if err := database.Connection.Model(&model.Notification{}).
		Where("user_id = ?", session.ActiveSignin.UserID).
		Where("deployment_id = ?", deployment.ID).
		Where("is_read = false").
		Where("is_archived = false").
		Where("(expires_at IS NULL OR expires_at > ?)", time.Now()).
		Count(&count).Error; err != nil {
		log.Printf("Failed to count unread notifications: %v", err)
		return handler.SendInternalServerError(c, nil, "Failed to count unread notifications")
	}

	return handler.SendSuccess(c, model.UnreadCountResponse{
		Count: count,
	})
}

func GetChannelCounts(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	channelCounts := model.GetChannelCounts(*session.ActiveSignin.UserID, session)

	return handler.SendSuccess(c, channelCounts)
}

// MarkAsRead marks a notification as read
func MarkAsRead(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	deployment := handler.GetDeployment(c)

	// Parse notification ID
	notificationID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid notification ID")
	}

	// Find and update the notification
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

	// Mark as read
	notification.MarkAsRead()

	// Update in database
	if err := database.Connection.Save(&notification).Error; err != nil {
		log.Printf("Failed to update notification: %v", err)
		return handler.SendInternalServerError(c, nil, "Failed to update notification")
	}

	return handler.SendSuccess(c, fiber.Map{
		"message": "Notification marked as read",
		"success": true,
	})
}

// MarkAllAsRead marks all notifications as read for the current user
func MarkAllAsRead(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	deployment := handler.GetDeployment(c)

	// Update all unread notifications
	result := database.Connection.Model(&model.Notification{}).
		Where("user_id = ?", session.ActiveSignin.UserID).
		Where("deployment_id = ?", deployment.ID).
		Where("is_read = false").
		Where("is_archived = false").
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

// Delete archives a notification (soft delete)
func Delete(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	deployment := handler.GetDeployment(c)

	// Parse notification ID
	notificationID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid notification ID")
	}

	// Find the notification
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

	// Archive the notification
	notification.Archive()

	// Update in database
	if err := database.Connection.Save(&notification).Error; err != nil {
		log.Printf("Failed to archive notification: %v", err)
		return handler.SendInternalServerError(c, nil, "Failed to archive notification")
	}

	return handler.SendSuccess(c, fiber.Map{
		"message": "Notification deleted",
		"success": true,
	})
}

// Get retrieves a single notification
func Get(c *fiber.Ctx) error {
	session := handler.GetSession(c)
	if session == nil {
		return handler.SendUnauthorized(c, nil, "Unauthorized")
	}

	deployment := handler.GetDeployment(c)

	// Parse notification ID
	notificationID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid notification ID")
	}

	// Find the notification
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
