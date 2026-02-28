package apiauthapp

import (
	"encoding/base64"
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

func NewHandler() *Handler {
	return &Handler{
		service: NewService(),
	}
}

func (h *Handler) getApiAuthAppSession(c *fiber.Ctx) (*model.ApiAuthAppSession, error) {
	session := handler.GetSession(c)
	if session == nil {
		return nil, errors.New("session required")
	}
	deployment := handler.GetDeployment(c)
	return h.service.GetActiveApiAuthAppSession(session.ID, deployment.ID)
}

func (h *Handler) GetSession(c *fiber.Ctx) error {
	apiAuthAppSession, err := h.getApiAuthAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active API auth app session")
	}

	deployment := handler.GetDeployment(c)

	apiAuthApp, err := h.service.GetApiAuthApp(deployment.ID, apiAuthAppSession.AppSlug)
	if err != nil {
		return handler.SendBadRequest(c, nil, "Invalid API auth app session")
	}

	return handler.SendSuccess(c, map[string]any{
		"session_id": strconv.FormatUint(apiAuthAppSession.ID, 10),
		"api_auth_app": ApiAuthAppInfo{
			AppSlug:     apiAuthApp.AppSlug,
			Name:        apiAuthApp.Name,
			KeyPrefix:   apiAuthApp.KeyPrefix,
			Description: apiAuthApp.Description,
			IsActive:    apiAuthApp.IsActive,
			RateLimits:  convertRateLimits(apiAuthApp.RateLimits),
		},
	})
}

func (h *Handler) GetKeys(c *fiber.Ctx) error {
	apiAuthAppSession, err := h.getApiAuthAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active API auth app session")
	}

	deployment := handler.GetDeployment(c)

	status := c.Query("status", "")
	includeInactive := c.QueryBool("include_inactive", false)

	keys, err := h.service.GetKeys(deployment.ID, apiAuthAppSession.AppSlug, status, includeInactive)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, keys)
}

func (h *Handler) CreateKey(c *fiber.Ctx) error {
	apiAuthAppSession, err := h.getApiAuthAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active API auth app session")
	}

	deployment := handler.GetDeployment(c)

	name := strings.TrimSpace(c.FormValue("name"))
	if name == "" {
		return handler.SendBadRequest(c, nil, "name is required")
	}

	var expiresAt *time.Time
	if value := strings.TrimSpace(c.FormValue("expires_at")); value != "" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return handler.SendBadRequest(c, nil, "expires_at must be RFC3339")
		}
		expiresAt = &parsed
	}

	result, err := h.service.CreateKey(deployment, apiAuthAppSession.AppSlug, name, expiresAt)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, result)
}

func (h *Handler) RotateKey(c *fiber.Ctx) error {
	apiAuthAppSession, err := h.getApiAuthAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active API auth app session")
	}

	deployment := handler.GetDeployment(c)

	keyID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "invalid key id")
	}

	result, err := h.service.RotateKey(deployment, apiAuthAppSession.AppSlug, keyID)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, result)
}

func (h *Handler) RevokeKey(c *fiber.Ctx) error {
	apiAuthAppSession, err := h.getApiAuthAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active API auth app session")
	}

	deployment := handler.GetDeployment(c)

	keyID, err := strconv.ParseUint(c.Params("id"), 10, 64)
	if err != nil {
		return handler.SendBadRequest(c, nil, "invalid key id")
	}

	reason := strings.TrimSpace(c.FormValue("reason"))

	if err := h.service.RevokeKey(deployment.ID, apiAuthAppSession.AppSlug, keyID, reason); err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, fiber.Map{"success": true})
}

func (h *Handler) GetAuditLogs(c *fiber.Ctx) error {
	apiAuthAppSession, err := h.getApiAuthAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active API auth app session")
	}

	deployment := handler.GetDeployment(c)

	limit, _ := strconv.Atoi(c.Query("limit", "100"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))
	outcome := c.Query("outcome", "")
	keyID := c.Query("key_id", "")
	startDate := c.Query("start_date", "")
	endDate := c.Query("end_date", "")
	cursorTSRaw := c.Query("cursor_ts", "")
	cursorID := c.Query("cursor_id", "")
	cursor := c.Query("cursor", "")

	if limit > 1000 {
		limit = 1000
	}

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
		cursorID = parts[1]
	} else if cursorTSRaw != "" {
		parsed, err := time.Parse(time.RFC3339, cursorTSRaw)
		if err != nil {
			return handler.SendBadRequest(c, nil, "invalid cursor_ts (must be RFC3339)")
		}
		cursorTS = &parsed
	}

	logs, err := h.service.GetAuditLogs(deployment.ID, apiAuthAppSession.AppSlug, limit, offset, cursorTS, cursorID, outcome, keyID, startDate, endDate)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, logs)
}

func (h *Handler) GetAuditAnalytics(c *fiber.Ctx) error {
	apiAuthAppSession, err := h.getApiAuthAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active API auth app session")
	}

	deployment := handler.GetDeployment(c)

	startDate := c.Query("start_date", "")
	endDate := c.Query("end_date", "")
	keyID := c.Query("key_id", "")

	includeTopKeys := c.QueryBool("include_top_keys", false)
	includeTopPaths := c.QueryBool("include_top_paths", false)
	includeBlockedReasons := c.QueryBool("include_blocked_reasons", false)
	includeRateLimits := c.QueryBool("include_rate_limits", false)
	topLimit, _ := strconv.Atoi(c.Query("top_limit", "10"))

	if topLimit > 50 {
		topLimit = 50
	}

	analytics, err := h.service.GetAuditAnalytics(
		deployment.ID,
		apiAuthAppSession.AppSlug,
		startDate,
		endDate,
		keyID,
		includeTopKeys,
		includeTopPaths,
		includeBlockedReasons,
		includeRateLimits,
		topLimit,
	)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, analytics)
}

func (h *Handler) GetAuditTimeseries(c *fiber.Ctx) error {
	apiAuthAppSession, err := h.getApiAuthAppSession(c)
	if err != nil {
		return handler.SendUnauthorized(c, nil, "No active API auth app session")
	}

	deployment := handler.GetDeployment(c)

	startDate := c.Query("start_date", "")
	endDate := c.Query("end_date", "")
	interval := c.Query("interval", "hour")
	keyID := c.Query("key_id", "")

	timeseries, err := h.service.GetAuditTimeseries(deployment.ID, apiAuthAppSession.AppSlug, startDate, endDate, interval, keyID)
	if err != nil {
		return handler.SendInternalServerError(c, nil, err.Error())
	}

	return handler.SendSuccess(c, timeseries)
}
