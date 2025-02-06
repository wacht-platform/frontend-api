package user

import (
	"fmt"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
)

type Handler struct{


}

func NewHandler() *Handler {
	return &Handler{

	}
}


func (h *Handler) GetUser(c *fiber.Ctx) error {
	log.Println("GetUser: Retrieving session from context")
	session := handler.GetSession(c)
	log.Printf("GetUser: Session retrieved, sessionID = %d, ActiveSigninID = %d\n", session.ID, session.ActiveSigninID)
	log.Println("GetUser: Querying for the active sign-in using session ID and ActiveSigninID")

	var activeSignin *model.Signin
	err := database.Connection.
		Preload("User").
		Where("session_id = ? AND id = ?", session.ID, session.ActiveSigninID).
		First(&activeSignin).Error

	if err != nil {
		log.Printf("GetUser: Error finding active sign-in - %v\n", err)
		return handler.SendNotFound(c, nil, "Active sign-in not found")
	}
	log.Printf("GetUser: Active sign-in found: %+v\n", activeSignin)

	log.Println("GetUser: Querying for all sign-ins for the session")
	var allSignins []*model.Signin
	err = database.Connection.
		Preload("User").
		Where("session_id = ?", session.ID).
		Find(&allSignins).Error

	if err != nil {
		log.Printf("GetUser: Error retrieving all sign-ins - %v\n", err)
		return handler.SendInternalServerError(c, nil, "Failed to retrieve all sign-ins")
	}

	log.Printf("GetUser: Total sign-ins found for session: %d\n", len(allSignins))

	log.Println("GetUser: Preparing response with active sign-in and all sign-ins")
	response := map[string]interface{}{
		"active_signin": activeSignin,
		"all_signins":   allSignins,
	}

	log.Printf("GetUser: Response prepared: %+v\n", response)

	log.Println("GetUser: Returning success response")
	return handler.SendSuccess(c, response)
}















