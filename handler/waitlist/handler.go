package waitlist

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
)

type Handler struct {
	service *WaitlistService
}

func NewHandler() *Handler {
	return &Handler{
		service: NewWaitlistService(),
	}
}

func (h *Handler) JoinWaitlist(c *fiber.Ctx) error {
	b, validation := handler.Validate[JoinWaitlistRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	deployment := handler.GetDeployment(c)

	if deployment.Restrictions.SignUpMode != model.DeploymentRestrictionsSignUpModeWaitlist {
		return handler.SendBadRequest(c, nil, "Waitlist is not enabled for this deployment")
	}

	if err := h.service.ValidateJoinWaitlistRequest(b, deployment); err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	var errors []handler.Error
	if h.service.CheckEmailExistsInWaitlist(b.Email, deployment.ID) {
		errors = append(errors, handler.ErrEmailExists)
	}
	if h.service.CheckUserEmailExists(b.Email, deployment.ID) {
		errors = append(errors, handler.ErrEmailExists)
	}

	if len(errors) > 0 {
		return handler.SendBadRequest(c, nil, "Email already exists", errors...)
	}

	entry, err := h.service.CreateWaitlistEntry(b, deployment.ID)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to join waitlist")
	}

	return handler.SendSuccess(c, fiber.Map{
		"message": "Successfully joined waitlist",
		"entry":   entry,
	})
}
