package webhookapp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
)

type Handler struct {
	service *Service
}

type WebhookAppSessionResponse struct {
	SessionID  string           `json:"session_id"`
	WebhookApp model.WebhookApp `json:"webhook_app"`
}

func (h *Handler) getWebhookAppSession(c *fiber.Ctx) (*model.WebhookAppSession, error) {
	session := handler.GetSession(c)
	if session == nil {
		return nil, errors.New("session required")
	}
	deployment := handler.GetDeployment(c)
	return h.service.GetActiveWebhookAppSession(session.ID, deployment.ID)
}

func (h *Handler) GetSession(c *fiber.Ctx) error {
	webhookAppSession, err := h.getWebhookAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active webhook app session")
	}

	deployment := handler.GetDeployment(c)

	webhookApp, err := h.service.GetWebhookApp(deployment.ID, webhookAppSession.AppSlug)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, WebhookAppSessionResponse{
		SessionID:  strconv.FormatUint(webhookAppSession.ID, 10),
		WebhookApp: *webhookApp,
	})
}

func (h *Handler) GetSettings(c *fiber.Ctx) error {
	webhookAppSession, err := h.getWebhookAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active webhook app session")
	}

	deployment := handler.GetDeployment(c)
	webhookApp, err := h.service.GetWebhookApp(deployment.ID, webhookAppSession.AppSlug)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, WebhookSettingsResponse{
		FailureNotificationEmails: webhookApp.FailureNotificationEmails,
	})
}

func (h *Handler) UpdateSettings(c *fiber.Ctx) error {
	webhookAppSession, err := h.getWebhookAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active webhook app session")
	}

	deployment := handler.GetDeployment(c)
	req, validation := handler.Validate[UpdateWebhookSettingsRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	app, err := h.service.UpdateFailureNotificationEmails(
		deployment.ID,
		webhookAppSession.AppSlug,
		req.FailureNotificationEmails,
	)
	if err != nil {
		var vErr *ValidationError
		if errors.As(err, &vErr) {
			return handler.SendBadRequest(c, nil, vErr.Error())
		}
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, WebhookSettingsResponse{
		FailureNotificationEmails: app.FailureNotificationEmails,
	})
}

func (h *Handler) GetEndpoints(c *fiber.Ctx) error {
	webhookAppSession, err := h.getWebhookAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active webhook app session")
	}

	deployment := handler.GetDeployment(c)

	endpoints, err := h.service.GetEndpoints(deployment.ID, webhookAppSession.AppSlug)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, endpoints)
}

func (h *Handler) GetEvents(c *fiber.Ctx) error {
	webhookAppSession, err := h.getWebhookAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active webhook app session")
	}

	deployment := handler.GetDeployment(c)

	events, err := h.service.GetEvents(deployment.ID, webhookAppSession.AppSlug)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, events)
}

func (h *Handler) GetDeliveries(c *fiber.Ctx) error {
	webhookAppSession, err := h.getWebhookAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active webhook app session")
	}

	deployment := handler.GetDeployment(c)

	// Get query parameters
	limit := c.QueryInt("limit", 50)
	offset := c.QueryInt("offset", 0)
	status := c.Query("status", "")
	eventName := c.Query("event_name", "")
	endpointID := c.Query("endpoint_id", "")
	cursorTSRaw := c.Query("cursor_ts", "")
	cursorIDRaw := c.Query("cursor_id", "")
	cursor := c.Query("cursor", "")

	var cursorTS *time.Time
	if cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		parts := strings.SplitN(string(decoded), "|", 2)
		if len(parts) != 2 {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		ms, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return handler.SendBadRequest(c, nil, "invalid cursor")
		}
		ts := time.UnixMilli(ms).UTC()
		cursorTS = &ts
		cursorIDRaw = parts[1]
	} else if cursorTSRaw != "" {
		parsed, err := time.Parse(time.RFC3339, cursorTSRaw)
		if err != nil {
			return handler.SendBadRequest(c, nil, "invalid cursor_ts (must be RFC3339)")
		}
		cursorTS = &parsed
	}

	var cursorID *int64
	if cursorIDRaw != "" {
		parsed, err := strconv.ParseInt(cursorIDRaw, 10, 64)
		if err != nil {
			return handler.SendBadRequest(c, nil, "invalid cursor_id")
		}
		cursorID = &parsed
	}

	deliveries, err := h.service.GetDeliveries(deployment.ID, webhookAppSession.AppSlug, limit, offset, cursorTS, cursorID, status, eventName, endpointID)
	if err != nil {
		var vErr *ValidationError
		if errors.As(err, &vErr) {
			return handler.SendBadRequest(c, nil, vErr.Error())
		}
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, deliveries)
}

func (h *Handler) GetAnalytics(c *fiber.Ctx) error {
	webhookAppSession, err := h.getWebhookAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active webhook app session")
	}

	deployment := handler.GetDeployment(c)

	// Get query parameters
	startDate := c.Query("start_date", "")
	endDate := c.Query("end_date", "")
	endpointID := c.Query("endpoint_id", "")
	fields := c.Query("fields", "")

	// Parse fields parameter
	var fieldsList []string
	if fields != "" {
		fieldsList = strings.Split(fields, ",")
		for i := range fieldsList {
			fieldsList[i] = strings.TrimSpace(fieldsList[i])
		}
	}

	analytics, err := h.service.GetAnalytics(deployment.ID, webhookAppSession.AppSlug, startDate, endDate, endpointID, fieldsList)
	if err != nil {
		var vErr *ValidationError
		if errors.As(err, &vErr) {
			return handler.SendBadRequest(c, nil, vErr.Error())
		}
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, analytics)
}

func (h *Handler) GetTimeseries(c *fiber.Ctx) error {
	webhookAppSession, err := h.getWebhookAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active webhook app session")
	}

	deployment := handler.GetDeployment(c)

	// Get query parameters
	startDate := c.Query("start_date", "")
	endDate := c.Query("end_date", "")
	interval := c.Query("interval", "hour")
	endpointID := c.Query("endpoint_id", "")

	timeseries, err := h.service.GetTimeseries(deployment.ID, webhookAppSession.AppSlug, startDate, endDate, interval, endpointID)
	if err != nil {
		var vErr *ValidationError
		if errors.As(err, &vErr) {
			return handler.SendBadRequest(c, nil, vErr.Error())
		}
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, timeseries)
}

func (h *Handler) GetStats(c *fiber.Ctx) error {
	webhookAppSession, err := h.getWebhookAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active webhook app session")
	}

	deployment := handler.GetDeployment(c)

	stats, err := h.service.GetStats(deployment.ID, webhookAppSession.AppSlug)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, stats)
}

func (h *Handler) GetCatalog(c *fiber.Ctx) error {
	webhookAppSession, err := h.getWebhookAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active webhook app session")
	}

	deployment := handler.GetDeployment(c)

	catalog, err := h.service.GetCatalog(deployment.ID, webhookAppSession.AppSlug)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, catalog)
}

func (h *Handler) CreateEndpoint(c *fiber.Ctx) error {
	webhookAppSession, err := h.getWebhookAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active webhook app session")
	}

	deployment := handler.GetDeployment(c)

	req, validation := handler.Validate[CreateEndpointRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	req.Headers = extractHeaders(c)

	result, err := h.service.CreateEndpoint(deployment.ID, webhookAppSession.AppSlug, req)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, result.Endpoint)
}

func (h *Handler) UpdateEndpoint(c *fiber.Ctx) error {
	webhookAppSession, err := h.getWebhookAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active webhook app session")
	}

	deployment := handler.GetDeployment(c)

	endpointIDParam := c.Params("id")
	endpointID, err := strconv.ParseUint(endpointIDParam, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid endpoint ID")
	}

	req, validation := handler.Validate[UpdateEndpointRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	req.Headers = extractHeaders(c)

	result, err := h.service.UpdateEndpoint(deployment.ID, webhookAppSession.AppSlug, endpointID, req)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, result.Endpoint)
}

func (h *Handler) DeleteEndpoint(c *fiber.Ctx) error {
	webhookAppSession, err := h.getWebhookAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active webhook app session")
	}

	deployment := handler.GetDeployment(c)

	endpointIDParam := c.Params("id")
	endpointID, err := strconv.ParseUint(endpointIDParam, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid endpoint ID")
	}

	result, err := h.service.DeleteEndpoint(deployment.ID, webhookAppSession.AppSlug, endpointID)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, result)
}

func (h *Handler) RotateSecret(c *fiber.Ctx) error {
	webhookAppSession, err := h.getWebhookAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active webhook app session")
	}

	deployment := handler.GetDeployment(c)

	app, err := h.service.RotateSecret(deployment.ID, webhookAppSession.AppSlug)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, app)
}

func (h *Handler) ReplayDelivery(c *fiber.Ctx) error {
	webhookAppSession, err := h.getWebhookAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active webhook app session")
	}

	deployment := handler.GetDeployment(c)

	req, validation := handler.Validate[ReplayDeliveryRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	result, err := h.service.ReplayDelivery(deployment.ID, webhookAppSession.AppSlug, req)
	if err != nil {
		var vErr *ValidationError
		if errors.As(err, &vErr) {
			if vErr.Code != "" {
				return handler.SendBadRequest(
					c,
					nil,
					vErr.Error(),
					handler.Error{
						Code:    vErr.Code,
						Message: vErr.Error(),
					},
				)
			}
			return handler.SendBadRequest(c, nil, vErr.Error())
		}
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, result)
}

func (h *Handler) GetReplayTaskStatus(c *fiber.Ctx) error {
	webhookAppSession, err := h.getWebhookAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active webhook app session")
	}

	deployment := handler.GetDeployment(c)
	taskID := c.Params("task_id")
	if taskID == "" {
		return handler.SendBadRequest(c, nil, "task_id is required")
	}

	result, err := h.service.GetReplayTaskStatus(deployment.ID, webhookAppSession.AppSlug, taskID)
	if err != nil {
		var vErr *ValidationError
		if errors.As(err, &vErr) {
			return handler.SendBadRequest(c, nil, vErr.Error())
		}
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, result)
}

func (h *Handler) ListReplayTasks(c *fiber.Ctx) error {
	webhookAppSession, err := h.getWebhookAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active webhook app session")
	}

	deployment := handler.GetDeployment(c)
	limit := c.QueryInt("limit", 20)
	offset := c.QueryInt("offset", 0)

	result, err := h.service.ListReplayTasks(deployment.ID, webhookAppSession.AppSlug, limit, offset)
	if err != nil {
		var vErr *ValidationError
		if errors.As(err, &vErr) {
			return handler.SendBadRequest(c, nil, vErr.Error())
		}
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, result)
}

func (h *Handler) CancelReplayTask(c *fiber.Ctx) error {
	webhookAppSession, err := h.getWebhookAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active webhook app session")
	}

	deployment := handler.GetDeployment(c)
	taskID := c.Params("task_id")
	if taskID == "" {
		return handler.SendBadRequest(c, nil, "task_id is required")
	}

	result, err := h.service.CancelReplayTask(deployment.ID, webhookAppSession.AppSlug, taskID)
	if err != nil {
		var vErr *ValidationError
		if errors.As(err, &vErr) {
			return handler.SendBadRequest(c, nil, vErr.Error())
		}
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, result)
}

func (h *Handler) TestEndpoint(c *fiber.Ctx) error {
	webhookAppSession, err := h.getWebhookAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active webhook app session")
	}

	deployment := handler.GetDeployment(c)

	endpointIDParam := c.Params("id")
	endpointID, err := strconv.ParseUint(endpointIDParam, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid endpoint ID")
	}

	req, validation := handler.Validate[TestEndpointRequest](c)
	if validation != nil {
		return handler.SendBadRequest(c, validation, "Bad request body")
	}

	payload := map[string]any{}
	if err := json.Unmarshal([]byte(req.Payload), &payload); err != nil {
		return handler.SendBadRequest(c, nil, "Invalid payload")
	}

	result, err := h.service.TestEndpoint(deployment.ID, webhookAppSession.AppSlug, endpointID, req.EventName, payload)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, result)
}

func (h *Handler) GetDelivery(c *fiber.Ctx) error {
	webhookAppSession, err := h.getWebhookAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active webhook app session")
	}

	deployment := handler.GetDeployment(c)

	deliveryIDParam := c.Params("id")
	deliveryID, err := strconv.ParseInt(deliveryIDParam, 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid delivery ID")
	}

	delivery, err := h.service.GetDelivery(deployment.ID, webhookAppSession.AppSlug, deliveryID)
	if err != nil {
		var vErr *ValidationError
		if errors.As(err, &vErr) {
			return handler.SendBadRequest(c, nil, vErr.Error())
		}
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, delivery)
}

func extractHeaders(c *fiber.Ctx) map[string]string {
	headers := make(map[string]string)

	if form, err := c.MultipartForm(); err == nil {
		for key, values := range form.Value {
			if strings.HasPrefix(key, "headers[") && strings.HasSuffix(key, "]") && len(values) > 0 {
				headerKey := key[8 : len(key)-1]
				headers[headerKey] = values[0]
			}
		}
	}

	c.Context().PostArgs().VisitAll(func(key, value []byte) {
		k := string(key)
		if strings.HasPrefix(k, "headers[") && strings.HasSuffix(k, "]") {
			headerKey := k[8 : len(k)-1]
			headers[headerKey] = string(value)
		}
	})

	if len(headers) == 0 {
		return nil
	}
	return headers
}

func NewHandler() *Handler {
	return &Handler{
		service: NewService(),
	}
}
