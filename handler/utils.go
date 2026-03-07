package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/wacht-platform/frontend-api/model"
	"github.com/wacht-platform/frontend-api/utils"
)

func GetDeployment(c *fiber.Ctx) model.Deployment {
	deployment := c.Locals("deployment")

	return deployment.(model.Deployment)
}

func GetSession(c *fiber.Ctx) *model.Session {
	if sessionData := c.Locals("session_data"); sessionData != nil {
		return sessionData.(*model.Session)
	}

	deployment := c.Locals("deployment")
	if deployment == nil {
		return nil
	}

	sessionID := c.Locals("session")
	if sessionID == nil {
		return nil
	}

	session, err := GetSessionFromCacheOrDB(sessionID.(uint64))
	if err != nil {
		return nil
	}

	c.Locals("session_data", session)

	return session
}

func GetSessionFromCacheOrDB(sessionID uint64) (*model.Session, error) {
	return utils.GetSessionByID(sessionID)
}

func RemoveSessionFromCacheAndLocals(c *fiber.Ctx, id uint64) {
	utils.RemoveCachedSession(id)

	c.Locals("session_data", nil)
}
