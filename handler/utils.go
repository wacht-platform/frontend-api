package handler

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/utils"
)

func GetDeployment(c *fiber.Ctx) model.Deployment {
	deployment := c.Locals("deployment")

	return deployment.(model.Deployment)
}

func GetSession(c *fiber.Ctx) *model.Session {
	deployment := c.Locals("deployment")

	if deployment == nil {
		return nil
	}

	sessionID := c.Locals("session")

	if sessionID == nil {
		return nil
	}

	session, err := utils.GetSessionByID(sessionID.(uint64))
	if err != nil {
		return nil
	}

	return session
}

func RemoveSessionFromCache(id uint64) {
	utils.DeleteFromCache(fmt.Sprintf("session:%d", id))
}
