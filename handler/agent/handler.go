package agent

import (
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/utils"
)

type Handler struct {
	service *Service
}

func NewHandler() *Handler {
	return &Handler{
		service: NewService(),
	}
}

func (h *Handler) verifyAgentToken(c *fiber.Ctx) (string, *string, error) {
	token := c.Query("token")
	if token == "" {
		return "", nil, fiber.NewError(fiber.StatusUnauthorized, "Token required")
	}

	deployment := handler.GetDeployment(c)

	if deployment.KepPair == nil {
		return "", nil, fiber.NewError(fiber.StatusInternalServerError, "Deployment keypair not configured")
	}

	claims, err := utils.VerifyJWT(token, *deployment.KepPair, deployment.BackendHost)
	if err != nil {
		return "", nil, fiber.NewError(fiber.StatusUnauthorized, "Invalid token")
	}

	userID, ok := claims.Subject()
	if !ok {
		return "", nil, fiber.NewError(fiber.StatusUnauthorized, "Invalid token: missing subject")
	}

	var contextGroup *string
	audiences, ok := claims.Audience()
	if ok && len(audiences) > 0 && audiences[0] != "" {
		contextGroup = &audiences[0]
	}

	return userID, contextGroup, nil
}

func (h *Handler) ListContexts(c *fiber.Ctx) error {
	_, contextGroup, err := h.verifyAgentToken(c)
	if err != nil {
		return err
	}

	deployment := handler.GetDeployment(c)

	params := ListContextsRequest{
		Limit:  c.QueryInt("limit", 10),
		Offset: c.QueryInt("offset", 0),
		Status: c.Query("status"),
		Search: c.Query("search"),
	}

	response, err := h.service.ListContexts(deployment.ID, contextGroup, params)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, response)
}

func (h *Handler) CreateContext(c *fiber.Ctx) error {
	_, contextGroup, err := h.verifyAgentToken(c)
	if err != nil {
		return err
	}

	title := c.FormValue("title")
	if title == "" {
		return handler.SendBadRequest(c, nil, "Title is required")
	}

	var systemInstructions *string
	if si := c.FormValue("system_instructions"); si != "" {
		systemInstructions = &si
	}

	req := CreateContextRequest{
		Title:              title,
		SystemInstructions: systemInstructions,
	}

	deployment := handler.GetDeployment(c)

	context, err := h.service.CreateContext(deployment.ID, contextGroup, req)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, context)
}

func (h *Handler) GetContext(c *fiber.Ctx) error {
	_, contextGroup, err := h.verifyAgentToken(c)
	if err != nil {
		return err
	}

	contextIDStr := c.Params("id")
	contextID, err := strconv.ParseUint(contextIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	deployment := handler.GetDeployment(c)

	context, err := h.service.GetContext(deployment.ID, contextGroup, contextID)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, context)
}

func (h *Handler) DeleteContext(c *fiber.Ctx) error {
	_, contextGroup, err := h.verifyAgentToken(c)
	if err != nil {
		return err
	}

	contextIDStr := c.Params("id")
	contextID, err := strconv.ParseUint(contextIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	deployment := handler.GetDeployment(c)

	if err := h.service.DeleteContext(deployment.ID, contextGroup, contextID); err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *Handler) GetContextMessages(c *fiber.Ctx) error {
	_, contextGroup, err := h.verifyAgentToken(c)
	if err != nil {
		return err
	}

	contextIDStr := c.Params("id")
	contextID, err := strconv.ParseUint(contextIDStr, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, err.Error())
	}

	limit := c.QueryInt("limit", 50)
	if limit > 100 {
		limit = 100
	}

	beforeID := c.Query("before_id")
	afterID := c.Query("after_id")

	deployment := handler.GetDeployment(c)

	messages, hasMore, err := h.service.GetContextMessages(deployment.ID, contextGroup, contextID, limit, beforeID, afterID)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, ListMessagesResponse{
		Data:    messages,
		HasMore: hasMore,
	})
}
