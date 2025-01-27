package session

import (
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"gorm.io/gorm"
)

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) GetCurrentSession(c *fiber.Ctx) error {
	sessionID := c.Locals("session").(uint)

	session := new(model.Session)

	err := database.Connection.Preload("ActiveSignIn").
		Preload("ActiveSignIn.User").
		Preload("ActiveSignIn.User.UserEmailAddresses").
		Preload("ActiveSignIn.User.UserEmailAddresses.SocialConnection").
		Preload("SignIns").
		Preload("SignIns.User").
		Where("id = ?", sessionID).
		First(session).Error
	if err != nil {
		return handler.SendNotFound(c, nil, "Session not found")
	}

	return c.JSON(session)
}

func (h *Handler) SwitchActiveSignIn(c *fiber.Ctx) error {
	session := handler.GetSession(c)

	signInId, err := strconv.ParseUint(c.Query("sign_in_id"), 10, 64)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid sign in ID")
	}

	validSignIn := false
	for _, signIn := range session.SignIns {
		if signIn.ID == uint(signInId) {
			session.ActiveSignIn = signIn
			validSignIn = true
			break
		}
	}

	if !validSignIn {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid sign in ID")
	}

	session.ActiveSignInID = uint(signInId)

	handler.RemoveSessionFromCache(session.ID)

	database.Connection.Save(session)

	return handler.SendSuccess(c, session)
}

func (h *Handler) SignOut(c *fiber.Ctx) error {
	session := handler.GetSession(c)

	signInIdStr := c.Query("sign_in_id")

	if signInIdStr == "" {
		signInId, err := strconv.ParseUint(signInIdStr, 10, 64)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "Invalid sign in ID")
		}

		signIn := new(model.SignIn)
		count := database.Connection.Where("id = ? AND session_id = ?", signInId, session.ID).First(signIn).RowsAffected

		if count == 0 {
			return fiber.NewError(fiber.StatusBadRequest, "Sign in not found")
		}

		err = database.Connection.Transaction(func(tx *gorm.DB) error {
			tx.Delete(signIn)
			tx.Model(session).Update("active_sign_in_id", 0)
			return nil
		})
		if err != nil {
			return handler.SendInternalServerError(c, nil, "Failed to sign out")
		}

		handler.RemoveSessionFromCache(session.ID)
		return handler.SendSuccess(c, session)
	} else {
		err := database.Connection.Transaction(func(tx *gorm.DB) error {
			tx.Model(session).Update("active_sign_in_id", 0)
			tx.Where("session_id = ?", session.ID).Delete(&model.SignIn{})
			return nil
		})
		if err != nil {
			return handler.SendInternalServerError(c, nil, "Failed to sign out")
		}

		handler.RemoveSessionFromCache(session.ID)
		return handler.SendSuccess(c, session)
	}
}
