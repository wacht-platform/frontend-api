package deployment

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/model"
	"gorm.io/gorm"
)

func GetDeployment(c *fiber.Ctx) error {
	deployment := handler.GetDeployment(c)
	deployment.KepPair = nil

	return handler.SendSuccess(c, deployment)
}

func GetMetadata(c *fiber.Ctx) error {
	deployment := handler.GetDeployment(c)

	return handler.SendSuccess(c, deployment.UISettings)
}

func GetJwk(c *fiber.Ctx) error {
	deployment := handler.GetDeployment(c)

	return handler.SendSuccess(c, deployment.KepPair)
}

func ValidateInvitation(c *fiber.Ctx) error {
	token := c.Query("token")
	if token == "" {
		return handler.SendBadRequest(c, nil, "Token is required")
	}

	deployment := handler.GetDeployment(c)

	var invitation model.DeploymentInvitation
	err := database.Connection.
		Where("token = ? AND deployment_id = ? AND expiry > ?", token, deployment.ID, time.Now()).
		First(&invitation).Error

	if err == gorm.ErrRecordNotFound {
		response := ValidateInvitationResponse{
			Valid:     false,
			Message:   "Invalid or expired invitation",
			ErrorCode: handler.ErrCodeInvalidInvitationToken,
		}
		return handler.SendSuccess(c, response)
	} else if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to validate invitation")
	}

	response := ValidateInvitationResponse{
		Valid:     true,
		FirstName: invitation.FirstName,
		LastName:  invitation.LastName,
		Email:     invitation.EmailAddress,
	}
	return handler.SendSuccess(c, response)
}
