package handler

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/utils"
	"gorm.io/gorm/clause"
)

func GetDeployment(c *fiber.Ctx) model.Deployment {
	deployment := c.Locals("deployment")

	return deployment.(model.Deployment)
}

func GetSession(c *fiber.Ctx) *model.Session {
	sessionID := c.Locals("session").(uint64)

	session, err := getSessionFromCache(sessionID)
	if err != nil {
		log.Println(err)
		session = getSessionAndSetToCache(sessionID)
	}

	return session
}

func RemoveSessionFromCache(id uint64) {
	utils.DeleteFromCache(fmt.Sprintf("session:%d", id))
}

func getSessionFromCache(id uint64) (*model.Session, error) {
	resp, err := http.Get(os.Getenv("CACHE_WORKER") + "?q=" + fmt.Sprintf("session:%d", id))
	if err == nil && resp.StatusCode == 200 {
		session := new(model.Session)
		if err := utils.GetFromCache(resp, session); err == nil {
			return session, nil
		}
	}
	return nil, fmt.Errorf("session not found in cache")
}

func getSessionAndSetToCache(sessionId uint64) *model.Session {
	session := new(model.Session)

	database.Connection.Where("id = ?", sessionId).
		Preload(clause.Associations).
		Preload("ActiveSignin.User").
		First(session)

	go utils.SetToCache(fmt.Sprintf("session:%d", sessionId), session, 3600)

	return session
}
