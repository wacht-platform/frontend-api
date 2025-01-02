package session

import (
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

	database.Connection.Preload("ActiveSignIn").Preload("SignIns").Where("id = ?", sessionID).First(session)

	return c.JSON(session)
}

func (h *Handler) DeleteSession(c *fiber.Ctx) error {
	_ = handler.GetSession(c)

	return c.SendStatus(fiber.StatusOK)
}

func (h *Handler) SwitchActiveSignIn(c *fiber.Ctx) error {
	session := c.Locals("session").(*model.Session)
	var body struct {
		SignInID uint `json:"sign_in_id"`
	}

	if err := c.BodyParser(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	validSignIn := false
	for _, signIn := range session.SignIns {
		if signIn.ID == body.SignInID {
			validSignIn = true
			break
		}
	}

	if !validSignIn {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid sign in ID")
	}

	session.ActiveSignInID = body.SignInID

	return c.SendStatus(fiber.StatusOK)
}
