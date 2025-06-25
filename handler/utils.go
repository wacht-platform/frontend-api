package handler

import (
	"encoding/json"
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
	cacheKey := fmt.Sprintf("session:%d", sessionID)

	cacheData, err := utils.GetMultipleFromCache(cacheKey)
	if err == nil {
		if sessionData, exists := cacheData[cacheKey]; exists {
			sessionBytes, _ := json.Marshal(sessionData)
			session := new(model.Session)
			if json.Unmarshal(sessionBytes, session) == nil {
				return session, nil
			}
		}
	}

	return utils.GetSessionByID(sessionID)
}

func RemoveSessionFromCache(id uint64) {
	utils.DeleteFromCache(fmt.Sprintf("session:%d", id))
}

func RemoveSessionFromCacheAndLocals(c *fiber.Ctx, id uint64) {
	utils.DeleteFromCache(fmt.Sprintf("session:%d", id))

	c.Locals("session_data", nil)
}
