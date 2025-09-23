package deployment

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
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

func AcceptInvitation(c *fiber.Ctx) error {
	var req AcceptInvitationRequest
	if err := c.BodyParser(&req); err != nil {
		return handler.SendBadRequest(c, nil, "Invalid request body")
	}

	if req.Token == "" || req.Email == "" {
		return handler.SendBadRequest(c, nil, "Token and email are required")
	}

	deployment := handler.GetDeployment(c)

	err := database.Connection.Transaction(func(tx *gorm.DB) error {
		var invitation model.DeploymentInvitation
		err := tx.Where("token = ? AND email_address = ? AND deployment_id = ? AND expiry > ?",
			req.Token, req.Email, deployment.ID, time.Now()).
			First(&invitation).Error

		if err == gorm.ErrRecordNotFound {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid or expired invitation")
		} else if err != nil {
			return err
		}

		if err := tx.Delete(&invitation).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		if fiberErr, ok := err.(*fiber.Error); ok {
			return handler.SendBadRequest(c, nil, fiberErr.Message)
		}
		return handler.SendInternalServerError(c, err, "Failed to accept invitation")
	}

	response := AcceptInvitationResponse{
		Success: true,
		Message: "Invitation accepted successfully",
	}
	return handler.SendSuccess(c, response)
}
