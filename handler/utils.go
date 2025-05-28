package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
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
	database.Cache.Del(
		context.Background(),
		fmt.Sprintf("session:%d", id),
	)
}

func getSessionFromCache(id uint64) (*model.Session, error) {
	var session model.Session
	ctx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()

	v := database.Cache.Get(ctx, fmt.Sprintf("session:%d", id))
	if v.Err() != nil {
		return nil, v.Err()
	}

	if v.Val() == "" {
		return nil, fmt.Errorf("session not found")
	}

	err := json.Unmarshal([]byte(v.Val()), &session)
	if err != nil {
		return nil, err
	}

	return &session, nil
}

func getSessionAndSetToCache(sessionId uint64) *model.Session {
	session := new(model.Session)

	database.Connection.Where("id = ?", sessionId).
		Preload(clause.Associations).
		Preload("ActiveSignin.User").
		First(session)

	json, err := json.Marshal(session)
	if err != nil {
		return nil
	}

	cmd := database.Cache.Set(
		context.Background(),
		fmt.Sprintf("session:%d", sessionId),
		json,
		time.Hour,
	)
	if cmd.Err() != nil {
		return nil
	}

	return session
}
