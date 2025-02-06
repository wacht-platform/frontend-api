package user

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
)

type Handler struct{


}

func NewHandler() *Handler {
	return &Handler{

	}
}


func (h *Handler) GetUser(c *fiber.Ctx) error {
	fmt.Println("GetUser: Retrieving session from context")
	session := handler.GetSession(c)

	if session == nil {
		fmt.Println("GetUser: Session not found")
		return handler.SendNotFound(c, nil, "Session not found")
	}

	fmt.Printf("GetUser: Retrieved session: %+v\n", session)

	fmt.Println("GetUser: Fetching session with ActiveSignin and User details")
	err := database.Connection.Preload("ActiveSignin.User").
		Where("id = ?", session.ID).
		First(session).Error

	if err != nil {
		fmt.Printf("GetUser: Error fetching session details: %v\n", err)
		return handler.SendNotFound(c, nil, "Failed to load session details")
	}

	fmt.Printf("GetUser: Loaded session: %+v\n", session)

	if session.ActiveSignin == nil {
		fmt.Println("GetUser: No active sign-in found")
		return handler.SendNotFound(c, nil, "No active sign-in found")
	}

	fmt.Printf("GetUser: Active sign-in found: %+v\n", session.ActiveSignin)

	if session.ActiveSignin.User == nil {
		fmt.Println("GetUser: No active sign-in user found")
		return handler.SendNotFound(c, nil, "No active sign-in user found")
	}

	fmt.Printf("GetUser: Returning active user: %+v\n", session.ActiveSignin.User)

	return handler.SendSuccess(c, session.ActiveSignin.User)
}









