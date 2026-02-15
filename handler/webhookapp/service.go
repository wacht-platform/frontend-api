package webhookapp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/pkg/idgen"
	"github.com/ilabs/wacht-fe/service"
	"github.com/redis/go-redis/v9"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type Service struct{}

const replayIdempotencyTTLSeconds = 1800
const replayActiveCountTTLSeconds = 86400
const replayMaxActiveTasks = 3
const endpointRetryWindowMax = 7 * 24 * time.Hour
const replayReserveStatusExists = "exists"
const replayReserveStatusLimit = "limit"
const replayReserveStatusReserved = "reserved"

func endpointRetryDelay(attempt int32) time.Duration {
	switch attempt {
	case 1:
		return 30 * time.Second
	case 2:
		return 1 * time.Minute
	case 3:
		return 5 * time.Minute
	case 4:
		return 15 * time.Minute
	default:
		return 6 * time.Hour
	}
}

func maxEndpointAttemptsForRetryWindow(window time.Duration) int32 {
	var attempts int32 = 1
	var total time.Duration
	for {
		delay := endpointRetryDelay(attempts)
		if total+delay > window {
			break
		}
		total += delay
		attempts++
	}
	return attempts
}

var replayIdempotencyReserveScript = redis.NewScript(`
local idem_key = KEYS[1]
local active_key = KEYS[2]
local pending_value = ARGV[1]
local idem_ttl = tonumber(ARGV[2])
local max_active = tonumber(ARGV[3])
local active_ttl = tonumber(ARGV[4])

local existing = redis.call('GET', idem_key)
if existing then
  return {1, existing, 0}
end

local current_active = tonumber(redis.call('GET', active_key) or '0')
if current_active >= max_active then
  return {2, '', current_active}
end

redis.call('SET', idem_key, pending_value, 'EX', idem_ttl, 'NX')
local active_after = tonumber(redis.call('INCR', active_key))
if active_after == 1 then
  redis.call('EXPIRE', active_key, active_ttl)
end

if active_after > max_active then
  redis.call('DECR', active_key)
  local current_idem = redis.call('GET', idem_key)
  if current_idem == pending_value then
    redis.call('DEL', idem_key)
  end
  return {2, '', active_after - 1}
end

return {0, '', active_after}
`)

var replayIdempotencyFinalizeScript = redis.NewScript(`
local key = KEYS[1]
local expected_pending = ARGV[1]
local final_value = ARGV[2]
local ttl = tonumber(ARGV[3])
local existing = redis.call('GET', key)
if not existing then
  return 0
end
if existing ~= expected_pending then
  return -1
end
redis.call('SET', key, final_value, 'EX', ttl)
return 1
`)

var replaySlotRollbackScript = redis.NewScript(`
local idem_key = KEYS[1]
local active_key = KEYS[2]
local expected_pending = ARGV[1]

local current_idem = redis.call('GET', idem_key)
if current_idem == expected_pending then
  redis.call('DEL', idem_key)
end

local current_active = tonumber(redis.call('GET', active_key) or '0')
if current_active > 0 then
  current_active = tonumber(redis.call('DECR', active_key))
end
if current_active <= 0 then
  redis.call('DEL', active_key)
end

return 1
`)

var replayCancelScript = redis.NewScript(`
local snapshot_key = KEYS[1]
local active_key = KEYS[2]
local now = ARGV[1]
local ttl = tonumber(ARGV[2])

redis.call('HSET', snapshot_key, 'status', 'cancelled')
redis.call('HSET', snapshot_key, 'cancelled', '1')
redis.call('HSET', snapshot_key, 'cancelled_at', now)
redis.call('HSET', snapshot_key, 'completed_at', now)

local reserved = redis.call('HGET', snapshot_key, 'active_slot_reserved')
if reserved == '1' then
  redis.call('HSET', snapshot_key, 'active_slot_reserved', '0')
  local current_active = tonumber(redis.call('GET', active_key) or '0')
  if current_active > 0 then
    current_active = tonumber(redis.call('DECR', active_key))
  end
  if current_active <= 0 then
    redis.call('DEL', active_key)
  end
end

redis.call('EXPIRE', snapshot_key, ttl)
return 1
`)

func (s *Service) GetCatalog(deploymentID uint64, appSlug string) (*model.WebhookEventCatalog, error) {
	var app model.WebhookApp
	err := database.Connection.Where("deployment_id = ? AND app_slug = ?", deploymentID, appSlug).First(&app).Error
	if err != nil {
		return nil, fmt.Errorf("failed to fetch app: %w", err)
	}

	if app.EventCatalogSlug == nil || *app.EventCatalogSlug == "" {
		return nil, fmt.Errorf("no catalog assigned to this app")
	}

	var catalog model.WebhookEventCatalog
	err = database.Connection.Where("deployment_id = ? AND slug = ?", deploymentID, *app.EventCatalogSlug).First(&catalog).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("catalog not found")
		}
		return nil, fmt.Errorf("failed to fetch catalog: %w", err)
	}

	return &catalog, nil
}

func NewService() *Service {
	return &Service{}
}

type ValidationError struct {
	Message string
	Code    string
}

func (e *ValidationError) Error() string {
	return e.Message
}

func validationError(message string) error {
	return &ValidationError{Message: message}
}

func validationErrorCode(code string, message string) error {
	return &ValidationError{Message: message, Code: code}
}

const (
	ErrCodeReplayMaxIDsExceeded      = "REPLAY_MAX_IDS_EXCEEDED"
	ErrCodeReplayDateWindowExceeded  = "REPLAY_DATE_WINDOW_EXCEEDED"
	ErrCodeReplayConcurrencyExceeded = "REPLAY_CONCURRENCY_EXCEEDED"
)

var safeToken = regexp.MustCompile(`^[a-zA-Z0-9._:-]+$`)

func validateToken(field string, value string) error {
	if value == "" {
		return validationError(fmt.Sprintf("%s is required", field))
	}
	if !safeToken.MatchString(value) {
		return validationError(fmt.Sprintf("invalid %s", field))
	}
	return nil
}

func validateOptionalToken(field string, value string) error {
	if value == "" {
		return nil
	}
	if !safeToken.MatchString(value) {
		return validationError(fmt.Sprintf("invalid %s", field))
	}
	return nil
}

func getNestedValue(value interface{}, path string) (interface{}, bool) {
	current := value
	for _, part := range strings.Split(path, ".") {
		obj, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		next, exists := obj[part]
		if !exists {
			return nil, false
		}
		current = next
	}
	return current, true
}

func asFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint8:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	default:
		return 0, false
	}
}

func compareValues(a interface{}, b interface{}, op string) bool {
	if an, ok := asFloat64(a); ok {
		if bn, ok := asFloat64(b); ok {
			switch op {
			case "$gt":
				return an > bn
			case "$gte":
				return an >= bn
			case "$lt":
				return an < bn
			case "$lte":
				return an <= bn
			}
		}
	}

	as, aok := a.(string)
	bs, bok := b.(string)
	if aok && bok {
		switch op {
		case "$gt":
			return as > bs
		case "$gte":
			return as >= bs
		case "$lt":
			return as < bs
		case "$lte":
			return as <= bs
		}
	}

	return false
}

func evaluateCondition(fieldValue interface{}, exists bool, condition interface{}) bool {
	conditionMap, isMap := condition.(map[string]interface{})
	if !isMap {
		return exists && reflect.DeepEqual(fieldValue, condition)
	}

	if !exists {
		if raw, ok := conditionMap["$exists"]; ok {
			if expected, ok := raw.(bool); ok {
				return !expected
			}
		}
		return false
	}

	for op, expected := range conditionMap {
		switch op {
		case "$eq":
			if !reflect.DeepEqual(fieldValue, expected) {
				return false
			}
		case "$ne":
			if reflect.DeepEqual(fieldValue, expected) {
				return false
			}
		case "$gt", "$gte", "$lt", "$lte":
			if !compareValues(fieldValue, expected, op) {
				return false
			}
		case "$in":
			list, ok := expected.([]interface{})
			if !ok {
				return false
			}
			found := false
			for _, item := range list {
				if reflect.DeepEqual(fieldValue, item) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		case "$nin":
			list, ok := expected.([]interface{})
			if !ok {
				return false
			}
			for _, item := range list {
				if reflect.DeepEqual(fieldValue, item) {
					return false
				}
			}
		case "$contains":
			if list, ok := fieldValue.([]interface{}); ok {
				found := false
				for _, item := range list {
					if reflect.DeepEqual(item, expected) {
						found = true
						break
					}
				}
				if !found {
					return false
				}
				continue
			}
			s, sok := fieldValue.(string)
			sub, subok := expected.(string)
			if !sok || !subok || !strings.Contains(s, sub) {
				return false
			}
		case "$exists":
			exp, ok := expected.(bool)
			if !ok || exp != true {
				return false
			}
		default:
			// Unknown operator: no match.
			return false
		}
	}

	return true
}

func evaluateFilterRules(filterRules map[string]interface{}, payload map[string]interface{}) bool {
	for key, rule := range filterRules {
		switch key {
		case "$and":
			conditions, ok := rule.([]interface{})
			if !ok {
				return false
			}
			for _, c := range conditions {
				nested, ok := c.(map[string]interface{})
				if !ok || !evaluateFilterRules(nested, payload) {
					return false
				}
			}
		case "$or":
			conditions, ok := rule.([]interface{})
			if !ok {
				return false
			}
			match := false
			for _, c := range conditions {
				nested, ok := c.(map[string]interface{})
				if ok && evaluateFilterRules(nested, payload) {
					match = true
					break
				}
			}
			if !match {
				return false
			}
		default:
			fieldValue, exists := getNestedValue(payload, key)
			if !evaluateCondition(fieldValue, exists, rule) {
				return false
			}
		}
	}
	return true
}

func parseOptionalDate(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02",
		"2006-01-02 15:04:05",
	}
	var parsed time.Time
	var err error
	for _, layout := range layouts {
		parsed, err = time.Parse(layout, value)
		if err == nil {
			return parsed.UTC().Format("2006-01-02 15:04:05"), nil
		}
	}
	return "", validationError("invalid date format")
}

func parseOptionalDateTime(value string) (*time.Time, error) {
	if value == "" {
		return nil, nil
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			utc := parsed.UTC()
			return &utc, nil
		}
	}
	return nil, validationError("invalid date format")
}

func validateReplayDateWindow(startDate time.Time, endDate *time.Time) error {
	windowEnd := time.Now().UTC()
	if endDate != nil {
		windowEnd = endDate.UTC()
	}
	if windowEnd.Before(startDate) {
		return validationError("end_date must be greater than or equal to start_date")
	}
	if windowEnd.Sub(startDate.UTC()) > 48*time.Hour {
		return validationErrorCode(
			ErrCodeReplayDateWindowExceeded,
			"replay range cannot exceed 48 hours",
		)
	}
	return nil
}

func parseOptionalInt64(value string) (*int64, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return nil, validationError("invalid endpoint_id")
	}
	return &parsed, nil
}

var allowedStatuses = map[string]bool{
	"success":            true,
	"failed":             true,
	"permanently_failed": true,
	"filtered":           true,
}

func validateOptionalStatus(value string) error {
	if value == "" {
		return nil
	}
	if !allowedStatuses[value] {
		return validationError("invalid status")
	}
	return nil
}

func validateInterval(value string) (string, error) {
	switch value {
	case "minute", "hour", "day", "week", "month":
		return value, nil
	default:
		return "", validationError("invalid interval")
	}
}

func (s *Service) GetActiveWebhookAppSession(sessionID uint64, deploymentID uint64) (*model.WebhookAppSession, error) {
	var session model.WebhookAppSession
	now := time.Now()

	err := database.Connection.
		Where("session_id = ? AND deployment_id = ? AND (expires_at IS NULL OR expires_at > ?)", sessionID, deploymentID, now).
		Order("created_at DESC").
		First(&session).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("no active webhook app session")
		}
		return nil, fmt.Errorf("failed to fetch webhook app session: %w", err)
	}

	return &session, nil
}

func (s *Service) GetWebhookApp(deploymentID uint64, appSlug string) (*model.WebhookApp, error) {
	var app model.WebhookApp
	err := database.Connection.
		Where("deployment_id = ? AND app_slug = ?", deploymentID, appSlug).
		First(&app).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("webhook app not found")
		}
		return nil, fmt.Errorf("failed to fetch webhook app: %w", err)
	}

	return &app, nil
}

func (s *Service) GetEndpoints(deploymentID uint64, appSlug string) ([]EndpointWithSubscriptions, error) {
	var endpoints []model.WebhookEndpoint
	err := database.Connection.
		Where("deployment_id = ? AND app_slug = ?", deploymentID, appSlug).
		Find(&endpoints).Error

	if err != nil {
		return nil, fmt.Errorf("failed to fetch endpoints: %w", err)
	}

	result := make([]EndpointWithSubscriptions, len(endpoints))
	for i, endpoint := range endpoints {
		subs, err := s.loadEndpointSubscriptions(endpoint.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch endpoint subscriptions: %w", err)
		}

		result[i] = EndpointWithSubscriptions{
			WebhookEndpoint:  endpoint,
			SubscribedEvents: extractEventNames(subs),
			Subscriptions:    subs,
		}
	}

	return result, nil
}

func extractEventNames(subs []EventSubscription) []string {
	events := make([]string, 0, len(subs))
	for _, sub := range subs {
		events = append(events, sub.EventName)
	}
	return events
}

func normalizeRequestedSubscriptions(subscriptionsJSON string, subscribedEvents []string) ([]EventSubscription, error) {
	subs := make([]EventSubscription, 0)
	if strings.TrimSpace(subscriptionsJSON) != "" {
		if err := json.Unmarshal([]byte(subscriptionsJSON), &subs); err != nil {
			return nil, validationError("invalid subscriptions payload")
		}
	} else {
		for _, eventName := range subscribedEvents {
			name := strings.TrimSpace(eventName)
			if name == "" {
				continue
			}
			subs = append(subs, EventSubscription{EventName: name})
		}
	}

	if len(subs) == 0 {
		return nil, validationError("at least one subscription is required")
	}

	seen := map[string]struct{}{}
	normalized := make([]EventSubscription, 0, len(subs))
	for _, sub := range subs {
		name := strings.TrimSpace(sub.EventName)
		if name == "" {
			return nil, validationError("subscription event_name is required")
		}
		if err := validateToken("event_name", name); err != nil {
			return nil, err
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		sub.EventName = name
		normalized = append(normalized, sub)
	}

	return normalized, nil
}

func (s *Service) loadEndpointSubscriptions(endpointID uint64) ([]EventSubscription, error) {
	var rows []model.WebhookEndpointSubscription
	if err := database.Connection.
		Where("endpoint_id = ?", endpointID).
		Order("event_name ASC").
		Find(&rows).Error; err != nil {
		return nil, err
	}

	subs := make([]EventSubscription, 0, len(rows))
	for _, row := range rows {
		sub := EventSubscription{
			EventName: row.EventName,
		}
		if len(row.FilterRules) > 0 {
			sub.FilterRules = make(map[string]interface{}, len(row.FilterRules))
			for k, v := range row.FilterRules {
				sub.FilterRules[k] = v
			}
		}
		subs = append(subs, sub)
	}

	return subs, nil
}

type WebhookAppEvent struct {
	DeploymentID   uint64         `json:"deployment_id,string"`
	AppSlug        string         `json:"app_slug"`
	EventName      string         `json:"event_name"`
	Description    *string        `json:"description,omitempty"`
	Group          *string        `json:"group,omitempty"`
	Schema         map[string]any `json:"schema,omitempty"`
	ExamplePayload map[string]any `json:"example_payload,omitempty"`
	IsArchived     bool           `json:"is_archived"`
	CreatedAt      time.Time      `json:"created_at"`
}

func (s *Service) GetEvents(deploymentID uint64, appSlug string) ([]WebhookAppEvent, error) {
	return s.fetchCatalogEvents(deploymentID, appSlug)
}

func (s *Service) fetchCatalogEvents(deploymentID uint64, appSlug string) ([]WebhookAppEvent, error) {
	var result struct {
		Events    []byte
		CreatedAt time.Time
	}

	err := database.Connection.Table("webhook_event_catalogs").
		Select("webhook_event_catalogs.events, webhook_event_catalogs.created_at").
		Joins("JOIN webhook_apps ON webhook_apps.event_catalog_slug = webhook_event_catalogs.slug AND webhook_apps.deployment_id = webhook_event_catalogs.deployment_id").
		Where("webhook_apps.deployment_id = ? AND webhook_apps.app_slug = ?", deploymentID, appSlug).
		Scan(&result).Error

	if err != nil {
		return nil, fmt.Errorf("failed to fetch catalog events: %w", err)
	}

	if result.Events == nil {
		return []WebhookAppEvent{}, nil
	}

	var eventDefs []struct {
		Name           string         `json:"name"`
		Description    string         `json:"description"`
		Group          *string        `json:"group"`
		Schema         map[string]any `json:"schema"`
		ExamplePayload map[string]any `json:"example_payload"`
		IsArchived     bool           `json:"is_archived"`
	}

	if err := json.Unmarshal(result.Events, &eventDefs); err != nil {
		return nil, fmt.Errorf("failed to parse catalog events: %w", err)
	}

	events := make([]WebhookAppEvent, len(eventDefs))
	for i, def := range eventDefs {
		events[i] = WebhookAppEvent{
			DeploymentID:   deploymentID,
			AppSlug:        appSlug,
			EventName:      def.Name,
			Description:    &def.Description,
			Group:          def.Group,
			Schema:         def.Schema,
			ExamplePayload: def.ExamplePayload,
			IsArchived:     def.IsArchived,
			CreatedAt:      result.CreatedAt,
		}
	}

	return events, nil
}

type DeliveriesResponse struct {
	Data       []DeliveryListItem `json:"data"`
	Limit      int                `json:"limit"`
	HasMore    bool               `json:"has_more"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

type DeliveryListItem struct {
	DeliveryID     int64     `json:"id,string"`
	DeploymentID   int64     `json:"deployment_id,string"`
	AppSlug        string    `json:"app_slug"`
	EndpointID     int64     `json:"endpoint_id,string"`
	EventName      string    `json:"event_name"`
	EventNameAlias string    `json:"event_type"` // For frontend compatibility
	Status         string    `json:"status"`
	HTTPStatusCode *int32    `json:"http_status_code,omitempty"`
	ResponseStatus *int32    `json:"response_status,omitempty"` // For frontend compatibility
	ResponseTimeMs *int32    `json:"response_time_ms,omitempty"`
	AttemptNumber  int32     `json:"attempt_number"`
	MaxAttempts    int32     `json:"max_attempts"`
	Timestamp      time.Time `json:"timestamp"`
	CreatedAt      time.Time `json:"created_at"` // For frontend compatibility
}

func (s *Service) GetDeliveries(deploymentID uint64, appSlug string, limit int, offset int, cursorTS *time.Time, cursorID *int64, status string, eventName string, endpointID string) (*DeliveriesResponse, error) {
	ctx := context.Background()

	if err := validateToken("app_slug", appSlug); err != nil {
		return nil, err
	}
	if err := validateOptionalStatus(status); err != nil {
		return nil, err
	}
	if err := validateOptionalToken("event_name", eventName); err != nil {
		return nil, err
	}
	endpointIDParsed, err := parseOptionalInt64(endpointID)
	if err != nil {
		return nil, err
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}

	whereParts := []string{
		"deployment_id = ?",
		"app_slug = ?",
	}
	whereArgs := []any{deploymentID, appSlug}

	if endpointIDParsed != nil {
		whereParts = append(whereParts, "endpoint_id = ?")
		whereArgs = append(whereArgs, *endpointIDParsed)
	}

	if status != "" {
		whereParts = append(whereParts, "status = ?")
		whereArgs = append(whereArgs, status)
	}

	if eventName != "" {
		whereParts = append(whereParts, "event_name = ?")
		whereArgs = append(whereArgs, eventName)
	}

	if cursorTS != nil {
		cursorTime := cursorTS.UTC()
		if cursorID != nil {
			whereParts = append(whereParts, "(timestamp < ? OR (timestamp = ? AND delivery_id < ?))")
			whereArgs = append(whereArgs, cursorTime, cursorTime, *cursorID)
		} else {
			whereParts = append(whereParts, "timestamp < ?")
			whereArgs = append(whereArgs, cursorTime)
		}
	}

	query := fmt.Sprintf(
		"SELECT delivery_id, deployment_id, app_slug, endpoint_id, event_name, "+
			"status, http_status_code, response_time_ms, attempt_number, max_attempts, "+
			"timestamp "+
			"FROM webhook_logs_light "+
			"WHERE %s",
		strings.Join(whereParts, " AND "),
	)

	// Get paginated results
	query += " ORDER BY timestamp DESC, delivery_id DESC LIMIT 1 BY delivery_id LIMIT ?"
	queryArgs := append([]any{}, whereArgs...)
	queryArgs = append(queryArgs, limit+1)
	if cursorTS == nil {
		query += " OFFSET ?"
		queryArgs = append(queryArgs, offset)
	}

	rows, err := database.ClickHouseClient.Query(ctx, query, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch deliveries: %w", err)
	}
	defer rows.Close()

	deliveries := make([]DeliveryListItem, 0)
	for rows.Next() {
		var d DeliveryListItem
		err := rows.Scan(
			&d.DeliveryID,
			&d.DeploymentID,
			&d.AppSlug,
			&d.EndpointID,
			&d.EventName,
			&d.Status,
			&d.HTTPStatusCode,
			&d.ResponseTimeMs,
			&d.AttemptNumber,
			&d.MaxAttempts,
			&d.Timestamp,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan delivery: %w", err)
		}

		// Populate alias fields for frontend compatibility
		d.EventNameAlias = d.EventName
		d.ResponseStatus = d.HTTPStatusCode
		d.CreatedAt = d.Timestamp

		deliveries = append(deliveries, d)
	}

	hasMore := false
	var nextCursor string
	if len(deliveries) > limit {
		hasMore = true
		last := deliveries[limit-1]
		nextCursor = encodeDeliveryCursor(last.Timestamp, last.DeliveryID)
		deliveries = deliveries[:limit]
	} else if len(deliveries) > 0 {
		last := deliveries[len(deliveries)-1]
		nextCursor = encodeDeliveryCursor(last.Timestamp, last.DeliveryID)
	}

	return &DeliveriesResponse{
		Data:       deliveries,
		Limit:      limit,
		HasMore:    hasMore,
		NextCursor: nextCursor,
	}, nil
}

type DeliveryDetail struct {
	DeliveryID      int64     `json:"id,string"`
	DeploymentID    int64     `json:"deployment_id,string"`
	AppSlug         string    `json:"app_slug"`
	EndpointID      int64     `json:"endpoint_id,string"`
	EventName       string    `json:"event_name"`
	EventNameAlias  string    `json:"event_type"`
	Status          string    `json:"status"`
	HTTPStatusCode  *int32    `json:"http_status_code,omitempty"`
	ResponseStatus  *int32    `json:"response_status,omitempty"`
	ResponseTimeMs  *int32    `json:"response_time_ms,omitempty"`
	AttemptNumber   int32     `json:"attempt_number"`
	MaxAttempts     int32     `json:"max_attempts"`
	Payload         *string   `json:"payload,omitempty"`
	ResponseBody    *string   `json:"response_body,omitempty"`
	ResponseHeaders *string   `json:"response_headers,omitempty"`
	RequestHeaders  *string   `json:"request_headers,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
	CreatedAt       time.Time `json:"created_at"`
}

func (s *Service) GetDelivery(deploymentID uint64, appSlug string, deliveryID int64) ([]*DeliveryDetail, error) {
	ctx := context.Background()

	if err := validateToken("app_slug", appSlug); err != nil {
		return nil, err
	}

	query := `
		WITH delivery_info AS (
			SELECT
				delivery_id,
				deployment_id,
				app_slug,
				endpoint_id,
				event_name,
				status,
				http_status_code,
				response_time_ms,
				attempt_number,
				max_attempts,
				payload_size_bytes,
				timestamp
			FROM webhook_logs_light
			WHERE deployment_id = ? AND app_slug = ? AND delivery_id = ?
		)
		SELECT
			d.delivery_id,
			d.deployment_id,
			d.app_slug,
			d.endpoint_id,
			d.event_name,
			d.status,
			d.http_status_code,
			d.response_time_ms,
			d.attempt_number,
			d.max_attempts,
			f.payload,
			f.response_body,
			f.response_headers,
			f.request_headers,
			d.timestamp
		FROM delivery_info d
		INNER JOIN webhook_logs_full f
			ON d.delivery_id = f.delivery_id
			AND d.deployment_id = f.deployment_id
			AND d.app_slug = f.app_slug
			AND d.attempt_number = f.attempt_number
		WHERE d.delivery_id = ?
		ORDER BY d.attempt_number ASC`

	rows, err := database.ClickHouseClient.Query(ctx, query, deploymentID, appSlug, deliveryID, deliveryID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch delivery: %w", err)
	}
	defer rows.Close()

	var details []*DeliveryDetail

	for rows.Next() {
		var d DeliveryDetail
		var payload, responseBody, responseHeaders, requestHeaders sql.NullString

		err := rows.Scan(
			&d.DeliveryID,
			&d.DeploymentID,
			&d.AppSlug,
			&d.EndpointID,
			&d.EventName,
			&d.Status,
			&d.HTTPStatusCode,
			&d.ResponseTimeMs,
			&d.AttemptNumber,
			&d.MaxAttempts,
			&payload,
			&responseBody,
			&responseHeaders,
			&requestHeaders,
			&d.Timestamp,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan delivery: %w", err)
		}

		// Populate nullable fields
		if payload.Valid {
			d.Payload = &payload.String
		}
		if responseBody.Valid {
			d.ResponseBody = &responseBody.String
		}
		if responseHeaders.Valid {
			d.ResponseHeaders = &responseHeaders.String
		}
		if requestHeaders.Valid {
			d.RequestHeaders = &requestHeaders.String
		}

		// Populate alias fields for frontend compatibility
		d.EventNameAlias = d.EventName
		d.ResponseStatus = d.HTTPStatusCode
		d.CreatedAt = d.Timestamp

		details = append(details, &d)
	}

	if len(details) == 0 {
		return nil, fmt.Errorf("delivery not found")
	}

	return details, nil
}

func encodeDeliveryCursor(ts time.Time, deliveryID int64) string {
	payload := fmt.Sprintf("%d|%d", ts.UTC().UnixMilli(), deliveryID)
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

type AnalyticsResponse struct {
	TotalDeliveries   uint64   `json:"total_deliveries"`
	TotalEvents       uint64   `json:"total_events"`
	Successful        uint64   `json:"successful"`
	Failed            uint64   `json:"failed"`
	Filtered          uint64   `json:"filtered"`
	SuccessRate       float64  `json:"success_rate"`
	AvgResponseTimeMs *float64 `json:"avg_response_time_ms,omitempty"`
	P50ResponseTimeMs *float64 `json:"p50_response_time_ms,omitempty"`
	P95ResponseTimeMs *float64 `json:"p95_response_time_ms,omitempty"`
	P99ResponseTimeMs *float64 `json:"p99_response_time_ms,omitempty"`
	AvgPayloadSize    *float64 `json:"avg_payload_size,omitempty"`
}

type AnalyticsField string

const (
	FieldTotalEvents     AnalyticsField = "total_events"
	FieldSuccessful      AnalyticsField = "successful"
	FieldFailed          AnalyticsField = "failed"
	FieldFiltered        AnalyticsField = "filtered"
	FieldAvgResponseTime AnalyticsField = "avg_response_time_ms"
	FieldP50ResponseTime AnalyticsField = "p50_response_time_ms"
	FieldP95ResponseTime AnalyticsField = "p95_response_time_ms"
	FieldP99ResponseTime AnalyticsField = "p99_response_time_ms"
	FieldAvgPayloadSize  AnalyticsField = "avg_payload_size"
	FieldSuccessRate     AnalyticsField = "success_rate"
)

func (s *Service) GetAnalytics(deploymentID uint64, appSlug string, startDate, endDate, endpointID string, fields []string) (*AnalyticsResponse, error) {
	ctx := context.Background()

	if err := validateToken("app_slug", appSlug); err != nil {
		return nil, err
	}
	startDateTime, err := parseOptionalDateTime(startDate)
	if err != nil {
		return nil, err
	}
	endDateTime, err := parseOptionalDateTime(endDate)
	if err != nil {
		return nil, err
	}
	endpointIDParsed, err := parseOptionalInt64(endpointID)
	if err != nil {
		return nil, err
	}

	whereParts := []string{"deployment_id = ?", "app_slug = ?"}
	whereArgs := []any{deploymentID, appSlug}
	if endpointIDParsed != nil {
		whereParts = append(whereParts, "endpoint_id = ?")
		whereArgs = append(whereArgs, *endpointIDParsed)
	}

	if startDateTime != nil {
		whereParts = append(whereParts, "timestamp >= ?")
		whereArgs = append(whereArgs, *startDateTime)
		if endDateTime != nil {
			whereParts = append(whereParts, "timestamp <= ?")
			whereArgs = append(whereArgs, *endDateTime)
		}
	} else {
		whereParts = append(whereParts, "timestamp >= now() - INTERVAL 30 DAY")
	}

	if len(fields) == 0 {
		fields = []string{string(FieldSuccessRate)}
	}

	fieldSet := make(map[string]bool)
	for _, f := range fields {
		fieldSet[f] = true
	}

	selectParts := []string{}
	scanTargets := []any{}
	var stats model.WebhookDeliveryStatsRow

	if fieldSet[string(FieldSuccessRate)] || fieldSet[string(FieldSuccessful)] {
		selectParts = append(selectParts, "countIf(status = 'success') as successful_deliveries")
		scanTargets = append(scanTargets, &stats.SuccessfulDeliveries)
	}

	if fieldSet[string(FieldFailed)] {
		selectParts = append(selectParts, "countIf(status IN ('failed', 'permanently_failed')) as failed_deliveries")
		scanTargets = append(scanTargets, &stats.FailedDeliveries)
	}

	if fieldSet[string(FieldFiltered)] {
		selectParts = append(selectParts, "countIf(status = 'filtered') as filtered_deliveries")
		scanTargets = append(scanTargets, &stats.FilteredDeliveries)
	}

	if fieldSet[string(FieldAvgResponseTime)] {
		selectParts = append(selectParts, "avgOrNull(response_time_ms) as avg_response_time_ms")
		scanTargets = append(scanTargets, &stats.AvgResponseTimeMs)
	}

	if fieldSet[string(FieldP50ResponseTime)] {
		selectParts = append(selectParts, "quantileOrNull(0.5)(response_time_ms) as p50_response_time_ms")
		scanTargets = append(scanTargets, &stats.P50ResponseTimeMs)
	}

	if fieldSet[string(FieldP95ResponseTime)] {
		selectParts = append(selectParts, "quantileOrNull(0.95)(response_time_ms) as p95_response_time_ms")
		scanTargets = append(scanTargets, &stats.P95ResponseTimeMs)
	}

	if fieldSet[string(FieldP99ResponseTime)] {
		selectParts = append(selectParts, "quantileOrNull(0.99)(response_time_ms) as p99_response_time_ms")
		scanTargets = append(scanTargets, &stats.P99ResponseTimeMs)
	}

	if fieldSet[string(FieldAvgPayloadSize)] {
		selectParts = append(selectParts, "avgOrNull(payload_size_bytes) as avg_payload_size")
		scanTargets = append(scanTargets, &stats.AvgPayloadSize)
	}

	// Always need total_deliveries for success_rate
	if fieldSet[string(FieldSuccessRate)] || len(selectParts) == 0 {
		selectParts = append([]string{"count() as total_deliveries"}, selectParts...)
		scanTargets = append([]interface{}{&stats.TotalDeliveries}, scanTargets...)
	}

	query := fmt.Sprintf(
		"SELECT %s FROM webhook_logs_light WHERE %s",
		strings.Join(selectParts, ", "),
		strings.Join(whereParts, " AND "),
	)

	err = database.ClickHouseClient.QueryRow(ctx, query, whereArgs...).Scan(scanTargets...)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch analytics: %w", err)
	}

	response := &AnalyticsResponse{}

	if fieldSet[string(FieldTotalEvents)] {
		response.TotalEvents = stats.TotalEvents
	}
	if fieldSet[string(FieldSuccessful)] {
		response.Successful = stats.SuccessfulDeliveries
	}
	if fieldSet[string(FieldFailed)] {
		response.Failed = stats.FailedDeliveries
	}
	if fieldSet[string(FieldFiltered)] {
		response.Filtered = stats.FilteredDeliveries
	}
	if fieldSet[string(FieldAvgResponseTime)] {
		response.AvgResponseTimeMs = stats.AvgResponseTimeMs
	}
	if fieldSet[string(FieldP50ResponseTime)] {
		response.P50ResponseTimeMs = stats.P50ResponseTimeMs
	}
	if fieldSet[string(FieldP95ResponseTime)] {
		response.P95ResponseTimeMs = stats.P95ResponseTimeMs
	}
	if fieldSet[string(FieldP99ResponseTime)] {
		response.P99ResponseTimeMs = stats.P99ResponseTimeMs
	}
	if fieldSet[string(FieldAvgPayloadSize)] {
		response.AvgPayloadSize = stats.AvgPayloadSize
	}

	if fieldSet[string(FieldSuccessRate)] || fieldSet[string(FieldSuccessful)] {
		response.TotalDeliveries = stats.TotalDeliveries
		response.Successful = stats.SuccessfulDeliveries
		if stats.TotalDeliveries > 0 {
			response.SuccessRate = float64(stats.SuccessfulDeliveries) / float64(stats.TotalDeliveries) * 100.0
		}
	}

	return response, nil
}

type TimeseriesPoint struct {
	Timestamp            time.Time `json:"timestamp"`
	TotalEvents          int64     `json:"total_events"`
	TotalDeliveries      int64     `json:"total_deliveries"`
	SuccessfulDeliveries int64     `json:"successful_deliveries"`
	FailedDeliveries     int64     `json:"failed_deliveries"`
	FilteredDeliveries   int64     `json:"filtered_deliveries"`
	AvgResponseTimeMs    *float64  `json:"avg_response_time_ms,omitempty"`
	SuccessRate          float64   `json:"success_rate"`
}

type TimeseriesResponse struct {
	Data     []TimeseriesPoint `json:"data"`
	Interval string            `json:"interval"`
}

func (s *Service) GetTimeseries(deploymentID uint64, appSlug string, startDate, endDate, interval, endpointID string) (*TimeseriesResponse, error) {
	ctx := context.Background()

	if err := validateToken("app_slug", appSlug); err != nil {
		return nil, err
	}
	interval, err := validateInterval(interval)
	if err != nil {
		return nil, err
	}
	startDateTime, err := parseOptionalDateTime(startDate)
	if err != nil {
		return nil, err
	}
	endDateTime, err := parseOptionalDateTime(endDate)
	if err != nil {
		return nil, err
	}
	endpointIDParsed, err := parseOptionalInt64(endpointID)
	if err != nil {
		return nil, err
	}

	intervalFunc := "toStartOfHour"
	switch interval {
	case "minute":
		intervalFunc = "toStartOfMinute"
	case "hour":
		intervalFunc = "toStartOfHour"
	case "day":
		intervalFunc = "toStartOfDay"
	case "week":
		intervalFunc = "toStartOfWeek"
	case "month":
		intervalFunc = "toStartOfMonth"
	}

	whereParts := []string{"deployment_id = ?", "app_slug = ?"}
	whereArgs := []any{deploymentID, appSlug}
	if endpointIDParsed != nil {
		whereParts = append(whereParts, "endpoint_id = ?")
		whereArgs = append(whereArgs, *endpointIDParsed)
	}
	if startDateTime != nil {
		whereParts = append(whereParts, "timestamp >= ?")
		whereArgs = append(whereArgs, *startDateTime)
		if endDateTime != nil {
			whereParts = append(whereParts, "timestamp <= ?")
			whereArgs = append(whereArgs, *endDateTime)
		}
	} else {
		whereParts = append(whereParts, "timestamp >= now() - INTERVAL 30 DAY")
	}
	whereClause := strings.Join(whereParts, " AND ")

	deliveryQuery := fmt.Sprintf(
		"SELECT "+
			"%s(timestamp) as bucket, "+
			"toInt64(count()) as total_deliveries, "+
			"toInt64(countIf(status = 'success')) as successful_deliveries, "+
			"toInt64(countIf(status IN ('failed', 'permanently_failed'))) as failed_deliveries, "+
			"toInt64(countIf(status = 'filtered')) as filtered_deliveries, "+
			"avg(response_time_ms) as avg_response_time_ms "+
			"FROM webhook_logs_light "+
			"WHERE %s "+
			"GROUP BY bucket ORDER BY bucket ASC",
		intervalFunc, whereClause,
	)

	rows, err := database.ClickHouseClient.Query(ctx, deliveryQuery, whereArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch delivery timeseries: %w", err)
	}
	defer rows.Close()

	var deliveryPoints []model.WebhookDeliveryTimeseriesRow
	for rows.Next() {
		var p model.WebhookDeliveryTimeseriesRow
		err := rows.Scan(
			&p.Bucket,
			&p.TotalDeliveries,
			&p.SuccessfulDeliveries,
			&p.FailedDeliveries,
			&p.FilteredDeliveries,
			&p.AvgResponseTimeMs,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan delivery timeseries: %w", err)
		}
		deliveryPoints = append(deliveryPoints, p)
	}

	// Note: event_id was removed from schema, so we can't track distinct events
	// Setting event counts to 0 for all buckets

	// Merge results
	result := make([]TimeseriesPoint, len(deliveryPoints))
	for i, dp := range deliveryPoints {
		// event_id was removed, so total_events is always 0
		totalEvents := int64(0)

		successRate := 0.0
		if dp.TotalDeliveries > 0 {
			successRate = float64(dp.SuccessfulDeliveries) / float64(dp.TotalDeliveries) * 100.0
		}

		result[i] = TimeseriesPoint{
			Timestamp:            dp.Bucket,
			TotalEvents:          totalEvents,
			TotalDeliveries:      dp.TotalDeliveries,
			SuccessfulDeliveries: dp.SuccessfulDeliveries,
			FailedDeliveries:     dp.FailedDeliveries,
			FilteredDeliveries:   dp.FilteredDeliveries,
			AvgResponseTimeMs:    dp.AvgResponseTimeMs,
			SuccessRate:          successRate,
		}
	}

	return &TimeseriesResponse{
		Data:     result,
		Interval: interval,
	}, nil
}

func (s *Service) GetStats(deploymentID uint64, appSlug string) (*StatsResponse, error) {
	var endpointCount int64
	database.Connection.
		Model(&model.WebhookEndpoint{}).
		Where("deployment_id = ? AND app_slug = ?", deploymentID, appSlug).
		Count(&endpointCount)

	var eventCount int64
	events, err := s.fetchCatalogEvents(deploymentID, appSlug)
	if err != nil {
		eventCount = 0
	} else {
		eventCount = int64(len(events))
	}

	var endpointIDs []uint64
	database.Connection.
		Model(&model.WebhookEndpoint{}).
		Where("deployment_id = ? AND app_slug = ?", deploymentID, appSlug).
		Pluck("id", &endpointIDs)

	var pendingDeliveries int64
	if len(endpointIDs) > 0 {
		database.Connection.
			Model(&model.ActiveWebhookDelivery{}).
			Where("endpoint_id IN ?", endpointIDs).
			Count(&pendingDeliveries)
	}

	return &StatsResponse{
		EndpointCount:     endpointCount,
		EventCount:        eventCount,
		PendingDeliveries: pendingDeliveries,
	}, nil
}

func (s *Service) CreateEndpoint(deploymentID uint64, appSlug string, req *CreateEndpointRequest) (*CreateEndpointResponse, error) {
	tx := database.Connection.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	endpoint := model.WebhookEndpoint{
		ID:             idgen.NextID(),
		DeploymentID:   deploymentID,
		AppSlug:        appSlug,
		URL:            req.URL,
		Description:    req.Description,
		IsActive:       true,
		MaxRetries:     maxEndpointAttemptsForRetryWindow(endpointRetryWindowMax),
		TimeoutSeconds: 30,
		FailureCount:   0,
		AutoDisabled:   false,
	}

	if len(req.Headers) > 0 {
		headers := make(datatypes.JSONMap)
		for k, v := range req.Headers {
			headers[k] = v
		}
		endpoint.Headers = headers
	}

	if req.RateLimit != nil {
		endpoint.RateLimit = &datatypes.JSONMap{
			"duration_ms":  req.RateLimit.DurationMs,
			"max_requests": req.RateLimit.MaxRequests,
		}
	}

	if err := tx.Create(&endpoint).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to create endpoint: %w", err)
	}

	subscriptions, err := normalizeRequestedSubscriptions(req.Subscriptions, req.SubscribedEvents)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	for _, sub := range subscriptions {
		subscription := model.WebhookEndpointSubscription{
			EndpointID:   endpoint.ID,
			DeploymentID: deploymentID,
			AppSlug:      appSlug,
			EventName:    sub.EventName,
		}
		if len(sub.FilterRules) > 0 {
			filterRules := datatypes.JSONMap{}
			for k, v := range sub.FilterRules {
				filterRules[k] = v
			}
			subscription.FilterRules = filterRules
		}
		if err := tx.Create(&subscription).Error; err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("failed to create subscription: %w", err)
		}
	}

	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	subs, err := s.loadEndpointSubscriptions(endpoint.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch subscriptions: %w", err)
	}

	return &CreateEndpointResponse{
		Endpoint: EndpointWithSubscriptions{
			WebhookEndpoint:  endpoint,
			SubscribedEvents: extractEventNames(subs),
			Subscriptions:    subs,
		},
	}, nil
}

func (s *Service) UpdateEndpoint(deploymentID uint64, appSlug string, endpointID uint64, req *UpdateEndpointRequest) (*UpdateEndpointResponse, error) {
	tx := database.Connection.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	var endpoint model.WebhookEndpoint
	err := tx.Where("id = ? AND deployment_id = ? AND app_slug = ?", endpointID, deploymentID, appSlug).
		First(&endpoint).Error
	if err != nil {
		tx.Rollback()
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("endpoint not found")
		}
		return nil, fmt.Errorf("failed to fetch endpoint: %w", err)
	}

	endpoint.URL = req.URL
	endpoint.Description = req.Description

	if req.Headers != nil {
		headers := make(datatypes.JSONMap)
		for k, v := range req.Headers {
			headers[k] = v
		}
		endpoint.Headers = headers
	}
	if req.IsActive != nil {
		endpoint.IsActive = *req.IsActive
	}

	if req.RateLimit != nil {
		endpoint.RateLimit = &datatypes.JSONMap{
			"duration_ms":  req.RateLimit.DurationMs,
			"max_requests": req.RateLimit.MaxRequests,
		}
	}

	if err := tx.Save(&endpoint).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to update endpoint: %w", err)
	}

	if err := tx.Where("endpoint_id = ?", endpoint.ID).Delete(&model.WebhookEndpointSubscription{}).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to delete existing subscriptions: %w", err)
	}

	subscriptions, err := normalizeRequestedSubscriptions(req.Subscriptions, req.SubscribedEvents)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	for _, sub := range subscriptions {
		subscription := model.WebhookEndpointSubscription{
			EndpointID:   endpoint.ID,
			DeploymentID: deploymentID,
			AppSlug:      appSlug,
			EventName:    sub.EventName,
		}
		if len(sub.FilterRules) > 0 {
			filterRules := datatypes.JSONMap{}
			for k, v := range sub.FilterRules {
				filterRules[k] = v
			}
			subscription.FilterRules = filterRules
		}
		if err := tx.Create(&subscription).Error; err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("failed to create subscription: %w", err)
		}
	}

	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	subs, err := s.loadEndpointSubscriptions(endpoint.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch subscriptions: %w", err)
	}

	return &UpdateEndpointResponse{
		Endpoint: EndpointWithSubscriptions{
			WebhookEndpoint:  endpoint,
			SubscribedEvents: extractEventNames(subs),
			Subscriptions:    subs,
		},
	}, nil
}

func (s *Service) DeleteEndpoint(deploymentID uint64, appSlug string, endpointID uint64) (*DeleteEndpointResponse, error) {
	var endpoint model.WebhookEndpoint
	err := database.Connection.
		Where("id = ? AND deployment_id = ? AND app_slug = ?", endpointID, deploymentID, appSlug).
		First(&endpoint).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("endpoint not found")
		}
		return nil, fmt.Errorf("failed to fetch endpoint: %w", err)
	}

	if err := database.Connection.
		Where("endpoint_id = ?", endpointID).
		Delete(&model.WebhookEndpointSubscription{}).Error; err != nil {
		return nil, fmt.Errorf("failed to delete subscriptions: %w", err)
	}

	if err := database.Connection.Delete(&endpoint).Error; err != nil {
		return nil, fmt.Errorf("failed to delete endpoint: %w", err)
	}

	return &DeleteEndpointResponse{
		Deleted: true,
	}, nil
}

func (s *Service) RotateSecret(deploymentID uint64, appSlug string) (*model.WebhookApp, error) {
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("failed to generate secret: %w", err)
	}
	secret := base64.StdEncoding.EncodeToString(secretBytes)
	signingSecret := "whsec_" + secret

	var app model.WebhookApp
	err := database.Connection.
		Model(&app).
		Where("deployment_id = ? AND app_slug = ?", deploymentID, appSlug).
		Updates(map[string]interface{}{
			"signing_secret": signingSecret,
			"updated_at":     time.Now(),
		}).
		Error

	if err != nil {
		return nil, fmt.Errorf("failed to rotate secret: %w", err)
	}

	// Fetch updated app
	err = database.Connection.
		Where("deployment_id = ? AND app_slug = ?", deploymentID, appSlug).
		First(&app).Error

	if err != nil {
		return nil, fmt.Errorf("failed to fetch updated app: %w", err)
	}

	return &app, nil
}

func (s *Service) ReplayDelivery(deploymentID uint64, appSlug string, req *ReplayDeliveryRequest) (*ReplayDeliveryResponse, error) {
	normalizedIDs := make([]string, 0, len(req.DeliveryIDs))
	var rangeStartDate *time.Time
	var rangeEndDate *time.Time
	var rangeStatus string
	var rangeEventName string
	var rangeEndpointID *int64
	var idempotencyRedisKey string
	var idempotencyPendingValue string
	idempotencyKey := strings.TrimSpace(req.IdempotencyKey)

	for _, rawID := range req.DeliveryIDs {
		id := strings.TrimSpace(rawID)
		if id == "" {
			continue
		}
		if _, err := strconv.ParseInt(id, 10, 64); err != nil {
			continue
		}
		normalizedIDs = append(normalizedIDs, id)
	}

	if len(req.DeliveryIDs) > 0 && len(normalizedIDs) == 0 {
		return nil, validationError("delivery_ids must contain at least one valid numeric id")
	}
	if len(normalizedIDs) > 500 {
		return nil, validationErrorCode(
			ErrCodeReplayMaxIDsExceeded,
			"maximum 500 delivery_ids are allowed per replay",
		)
	}

	if len(normalizedIDs) == 0 {
		if err := validateOptionalStatus(req.Status); err != nil {
			return nil, err
		}
		if err := validateOptionalToken("event_name", req.EventName); err != nil {
			return nil, err
		}
		endpointIDParsed, err := parseOptionalInt64(req.EndpointID)
		if err != nil {
			return nil, err
		}
		startDT, err := parseOptionalDateTime(req.StartDate)
		if err != nil {
			return nil, err
		}
		endDT, err := parseOptionalDateTime(req.EndDate)
		if err != nil {
			return nil, err
		}
		if startDT == nil {
			return nil, validationError("start_date is required when delivery_ids are not provided")
		}
		if err := validateReplayDateWindow(*startDT, endDT); err != nil {
			return nil, err
		}

		rangeStartDate = startDT
		rangeEndDate = endDT
		rangeStatus = req.Status
		rangeEventName = req.EventName
		rangeEndpointID = endpointIDParsed
	}

	if idempotencyKey == "" {
		idempotencyKey = generateReplayIdempotencyKey()
	}
	idempotencyRedisKey = replayIdempotencyKey(appSlug, idempotencyKey)
	activeCountRedisKey := replayActiveCountKey(appSlug)
	idempotencyPendingValue = replayIdempotencyPendingValue()

	reserveStatus, existingValue, err := reserveReplayIdempotency(
		context.Background(),
		idempotencyRedisKey,
		activeCountRedisKey,
		idempotencyPendingValue,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to reserve replay idempotency key: %w", err)
	}
	if reserveStatus == replayReserveStatusExists && existingValue != "" {
		state, existingTaskID := parseReplayIdempotencyValue(existingValue)
		if state == "task" && existingTaskID != "" {
			return &ReplayDeliveryResponse{
				Status:  "queued",
				Message: "Replay already queued for this idempotency key",
				TaskID:  existingTaskID,
			}, nil
		}
		return &ReplayDeliveryResponse{
			Status:  "queued",
			Message: "Replay request is already being queued for this idempotency key",
		}, nil
	}
	if reserveStatus == replayReserveStatusLimit {
		return nil, validationErrorCode(
			ErrCodeReplayConcurrencyExceeded,
			"maximum 3 replay jobs can run at once for this app",
		)
	}

	natsService := service.GetNATS()

	var taskID string
	if len(normalizedIDs) == 0 {
		if rangeStartDate == nil {
			_ = rollbackReplaySlot(context.Background(), idempotencyRedisKey, activeCountRedisKey, idempotencyPendingValue)
			return nil, validationError("start_date is required for range replay")
		}
		taskID, err = natsService.PublishWebhookReplayBatchByDateRange(
			context.Background(),
			deploymentID,
			appSlug,
			*rangeStartDate,
			rangeEndDate,
			rangeStatus,
			rangeEventName,
			rangeEndpointID,
		)
		if err != nil {
			_ = rollbackReplaySlot(context.Background(), idempotencyRedisKey, activeCountRedisKey, idempotencyPendingValue)
			return nil, fmt.Errorf("failed to queue webhook replay range: %w", err)
		}
	} else {
		taskID, err = natsService.PublishWebhookReplayBatchByIDs(context.Background(), deploymentID, appSlug, normalizedIDs)
		if err != nil {
			_ = rollbackReplaySlot(context.Background(), idempotencyRedisKey, activeCountRedisKey, idempotencyPendingValue)
			return nil, fmt.Errorf("failed to queue webhook replay batch: %w", err)
		}
	}

	now := time.Now().UTC()
	snapshotKey := replayTaskSnapshotKey(appSlug, taskID)
	indexKey := replayTaskIndexKey(appSlug)
	pipe := database.Redis.TxPipeline()
	pipe.HSet(context.Background(), snapshotKey, map[string]interface{}{
		"task_id":              taskID,
		"app_slug":             appSlug,
		"deployment_id":        deploymentID,
		"status":               "queued",
		"created_at":           now.Format(time.RFC3339),
		"total_count":          len(normalizedIDs), // worker updates this for date-range replay tasks
		"processed_count":      0,
		"replayed_count":       0,
		"failed_count":         0,
		"active_slot_reserved": "1",
	})
	pipe.Expire(context.Background(), snapshotKey, 24*time.Hour)
	pipe.ZAdd(context.Background(), indexKey, redis.Z{
		Score:  float64(now.Unix()),
		Member: taskID,
	})
	pipe.Expire(context.Background(), indexKey, 24*time.Hour)
	if _, err := pipe.Exec(context.Background()); err != nil {
		_ = rollbackReplaySlot(context.Background(), idempotencyRedisKey, activeCountRedisKey, idempotencyPendingValue)
		return nil, fmt.Errorf("failed to persist replay task snapshot: %w", err)
	}

	if idempotencyRedisKey != "" {
		finalValue := replayIdempotencyFinalValue(taskID)
		if err := finalizeReplayIdempotency(
			context.Background(),
			idempotencyRedisKey,
			idempotencyPendingValue,
			finalValue,
		); err != nil {
			return nil, fmt.Errorf("failed to finalize replay idempotency key: %w", err)
		}
	}
	return &ReplayDeliveryResponse{
		Status:  "queued",
		Message: "Webhook deliveries queued for replay",
		TaskID:  taskID,
	}, nil
}

func replayTaskSnapshotKey(appSlug, taskID string) string {
	return fmt.Sprintf("worker:webhook:replay:%s:%s", appSlug, taskID)
}

func replayTaskIndexKey(appSlug string) string {
	return fmt.Sprintf("worker:webhook:replay:index:%s", appSlug)
}

func replayActiveCountKey(appSlug string) string {
	return fmt.Sprintf("worker:webhook:replay:active_count:%s", appSlug)
}

func replayIdempotencyKey(appSlug, idempotencyKey string) string {
	return fmt.Sprintf("worker:webhook:replay:idem:%s:%s", appSlug, idempotencyKey)
}

func replayIdempotencyPendingValue() string {
	return "pending"
}

func replayIdempotencyFinalValue(taskID string) string {
	return fmt.Sprintf("task:%s", taskID)
}

func parseReplayIdempotencyValue(value string) (state string, taskID string) {
	if value == "pending" {
		return "pending", ""
	}
	if strings.HasPrefix(value, "task:") {
		parts := strings.SplitN(value, ":", 2)
		if len(parts) == 2 {
			return "task", parts[1]
		}
	}
	return "", ""
}

func generateReplayIdempotencyKey() string {
	return fmt.Sprintf("auto_%d", idgen.NextID())
}

func reserveReplayIdempotency(
	ctx context.Context,
	idempotencyKey string,
	activeKey string,
	pendingValue string,
) (status string, existing string, err error) {
	result, err := replayIdempotencyReserveScript.Run(
		ctx,
		database.Redis,
		[]string{idempotencyKey, activeKey},
		pendingValue,
		replayIdempotencyTTLSeconds,
		replayMaxActiveTasks,
		replayActiveCountTTLSeconds,
	).Result()
	if err != nil {
		return "", "", err
	}

	values, ok := result.([]interface{})
	if !ok || len(values) < 3 {
		return "", "", fmt.Errorf("invalid idempotency reserve response")
	}

	flag, parseErr := strconv.ParseInt(fmt.Sprintf("%v", values[0]), 10, 64)
	if parseErr != nil {
		return "", "", fmt.Errorf("invalid idempotency reserve response flag: %w", parseErr)
	}
	if flag == 1 {
		return replayReserveStatusExists, fmt.Sprintf("%v", values[1]), nil
	}
	if flag == 2 {
		return replayReserveStatusLimit, "", nil
	}
	return replayReserveStatusReserved, "", nil
}

func finalizeReplayIdempotency(ctx context.Context, key string, pendingValue string, finalValue string) error {
	_, err := replayIdempotencyFinalizeScript.Run(
		ctx,
		database.Redis,
		[]string{key},
		pendingValue,
		finalValue,
		replayIdempotencyTTLSeconds,
	).Result()
	return err
}

func rollbackReplaySlot(ctx context.Context, idempotencyKey string, activeKey string, pendingValue string) error {
	_, err := replaySlotRollbackScript.Run(
		ctx,
		database.Redis,
		[]string{idempotencyKey, activeKey},
		pendingValue,
	).Result()
	return err
}

func parseInt64SnapshotField(value string) int64 {
	if value == "" {
		return 0
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func (s *Service) GetReplayTaskStatus(_ uint64, appSlug string, taskID string) (*ReplayTaskStatusResponse, error) {
	if err := validateToken("app_slug", appSlug); err != nil {
		return nil, err
	}
	if err := validateToken("task_id", taskID); err != nil {
		return nil, err
	}

	data, err := database.Redis.HGetAll(context.Background(), replayTaskSnapshotKey(appSlug, taskID)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch replay task: %w", err)
	}
	if len(data) == 0 {
		return nil, validationError("replay task not found")
	}

	result := &ReplayTaskStatusResponse{
		TaskID:        taskID,
		AppSlug:       appSlug,
		Status:        data["status"],
		CreatedAt:     data["created_at"],
		StartedAt:     data["started_at"],
		CompletedAt:   data["completed_at"],
		TotalCount:    parseInt64SnapshotField(data["total_count"]),
		Processed:     parseInt64SnapshotField(data["processed_count"]),
		ReplayedCount: parseInt64SnapshotField(data["replayed_count"]),
		FailedCount:   parseInt64SnapshotField(data["failed_count"]),
	}
	if last := parseInt64SnapshotField(data["last_delivery_id"]); last > 0 {
		result.LastDeliveryID = &last
	}

	if result.Status == "" {
		result.Status = "queued"
	}

	return result, nil
}

func (s *Service) CancelReplayTask(_ uint64, appSlug string, taskID string) (*ReplayTaskCancelResponse, error) {
	if err := validateToken("app_slug", appSlug); err != nil {
		return nil, err
	}
	if err := validateToken("task_id", taskID); err != nil {
		return nil, err
	}

	snapshotKey := replayTaskSnapshotKey(appSlug, taskID)
	ctx := context.Background()
	exists, err := database.Redis.Exists(ctx, snapshotKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to check replay task: %w", err)
	}
	if exists == 0 {
		return nil, validationError("replay task not found")
	}

	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := replayCancelScript.Run(
		ctx,
		database.Redis,
		[]string{snapshotKey, replayActiveCountKey(appSlug)},
		now,
		int((2 * time.Hour).Seconds()),
	).Result(); err != nil {
		return nil, fmt.Errorf("failed to cancel replay task: %w", err)
	}

	return &ReplayTaskCancelResponse{
		Status:  "cancelled",
		Message: "Replay task cancellation requested",
	}, nil
}

func (s *Service) ListReplayTasks(_ uint64, appSlug string, limit int, offset int) (*ReplayTaskListResponse, error) {
	if err := validateToken("app_slug", appSlug); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	taskIDs, err := database.Redis.ZRevRange(context.Background(), replayTaskIndexKey(appSlug), int64(offset), int64(offset+limit)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list replay tasks: %w", err)
	}

	hasMore := len(taskIDs) > limit
	if hasMore {
		taskIDs = taskIDs[:limit]
	}

	items := make([]ReplayTaskStatusResponse, 0, len(taskIDs))
	for _, taskID := range taskIDs {
		task, err := s.GetReplayTaskStatus(0, appSlug, taskID)
		if err != nil {
			continue
		}
		items = append(items, *task)
	}

	return &ReplayTaskListResponse{
		Data:    items,
		Limit:   limit,
		Offset:  offset,
		HasMore: hasMore,
	}, nil
}

func (s *Service) TestEndpoint(deploymentID uint64, appSlug string, endpointID uint64, eventName string, payload map[string]any) (*TestEndpointResponse, error) {
	var endpoint model.WebhookEndpoint
	err := database.Connection.
		Where("id = ? AND deployment_id = ? AND app_slug = ?", endpointID, deploymentID, appSlug).
		First(&endpoint).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("endpoint not found")
		}
		return nil, fmt.Errorf("failed to fetch endpoint: %w", err)
	}

	if !endpoint.IsActive {
		return &TestEndpointResponse{
			Success: false,
			Message: "Endpoint is not active",
		}, nil
	}

	var subscription model.WebhookEndpointSubscription
	err = database.Connection.
		Where("endpoint_id = ? AND deployment_id = ? AND app_slug = ? AND event_name = ?", endpointID, deploymentID, appSlug, eventName).
		First(&subscription).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return &TestEndpointResponse{
				Success: false,
				Message: "Endpoint is not subscribed to this event",
			}, nil
		}
		return nil, fmt.Errorf("failed to fetch endpoint subscription: %w", err)
	}

	var webhookApp model.WebhookApp
	err = database.Connection.
		Where("deployment_id = ? AND app_slug = ?", deploymentID, appSlug).
		First(&webhookApp).Error
	if err != nil {
		return nil, fmt.Errorf("failed to fetch webhook app: %w", err)
	}

	testPayload := payload
	if testPayload == nil {
		return nil, fmt.Errorf("test payload is required")
	}

	payloadBytes, err := json.Marshal(testPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to create test payload: %w", err)
	}

	webhookIDBytes := make([]byte, 16)
	if _, err := rand.Read(webhookIDBytes); err != nil {
		return nil, fmt.Errorf("failed to generate webhook ID: %w", err)
	}
	webhookID := hex.EncodeToString(webhookIDBytes)
	webhookTimestamp := time.Now().Unix()

	h := hmac.New(sha256.New, []byte(webhookApp.SigningSecret))
	fmt.Fprintf(h, "%s.%d", webhookID, webhookTimestamp)
	h.Write(payloadBytes)
	signature := hex.EncodeToString(h.Sum(nil))

	delivery := model.ActiveWebhookDelivery{
		ID:               idgen.NextID(),
		EndpointID:       endpointID,
		DeploymentID:     deploymentID,
		AppSlug:          appSlug,
		EventName:        eventName,
		Payload:          testPayload,
		FilterRules:      subscription.FilterRules,
		PayloadSizeBytes: int32(len(payloadBytes)),
		WebhookID:        webhookID,
		WebhookTimestamp: webhookTimestamp,
		Signature:        &signature,
		Attempts:         0,
		MaxAttempts:      endpoint.MaxRetries,
		NextRetryAt:      time.Now(),
	}

	if err := database.Connection.Create(&delivery).Error; err != nil {
		return nil, fmt.Errorf("failed to create test delivery: %w", err)
	}

	natsService := service.GetNATS()
	if err := natsService.PublishWebhookDelivery(context.Background(), delivery.ID, deploymentID); err != nil {
		fmt.Printf("Failed to publish test webhook to NATS: %v\n", err)
	}

	return &TestEndpointResponse{
		Success: true,
		Message: "Test webhook sent successfully",
	}, nil
}
