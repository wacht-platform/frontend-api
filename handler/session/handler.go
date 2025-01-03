package session

import (
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
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

func (h *Handler) DeleteSession(c *fiber.Ctx) error {
	_ = handler.GetSession(c)

	return c.SendStatus(fiber.StatusOK)
}

func (h *Handler) SwitchActiveSignIn(c *fiber.Ctx) error {
	session := c.Locals("session").(*model.Session)

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
	database.Connection.Save(session)

	return handler.SendSuccess(c, session)
}
