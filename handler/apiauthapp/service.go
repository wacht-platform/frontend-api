package apiauthapp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
	"gorm.io/gorm"
)

type Service struct{}

func NewService() *Service {
	return &Service{}
}

func (s *Service) GetActiveApiAuthAppSession(sessionID uint64, deploymentID uint64) (*model.ApiAuthAppSession, error) {
	var session model.ApiAuthAppSession
	now := time.Now()

	err := database.Connection.
		Where("session_id = ? AND deployment_id = ? AND (expires_at IS NULL OR expires_at > ?)", sessionID, deploymentID, now).
		Order("created_at DESC").
		First(&session).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("no active API auth app session")
		}
		return nil, fmt.Errorf("failed to fetch API auth app session: %w", err)
	}

	return &session, nil
}

func (s *Service) GetApiAuthApp(deploymentID uint64, appSlug string) (*model.ApiAuthApp, error) {
	type appWithRateLimits struct {
		model.ApiAuthApp
		RateLimits model.RateLimits `gorm:"column:rate_limits"`
	}

	var app appWithRateLimits
	err := database.Connection.
		Table("api_auth_apps a").
		Select("a.*, rls.rules as rate_limits").
		Joins("LEFT JOIN rate_limit_schemes rls ON rls.deployment_id = a.deployment_id AND rls.slug = a.rate_limit_scheme_slug").
		Where("a.deployment_id = ? AND a.app_slug = ? AND a.deleted_at IS NULL", deploymentID, appSlug).
		First(&app).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("API auth app not found")
		}
		return nil, fmt.Errorf("failed to fetch API auth app: %w", err)
	}

	app.ApiAuthApp.RateLimits = app.RateLimits
	return &app.ApiAuthApp, nil
}

func (s *Service) CreateKey(deployment model.Deployment, appSlug string, name string, expiresAt *time.Time) (*ApiKeyWithSecret, error) {
	var app model.ApiAuthApp
	if err := database.Connection.
		Where("deployment_id = ? AND app_slug = ? AND deleted_at IS NULL", deployment.ID, appSlug).
		First(&app).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("API auth app not found")
		}
		return nil, fmt.Errorf("failed to fetch API auth app: %w", err)
	}

	fullKey, keyHash, keySuffix, err := generateApiKey(app.KeyPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to generate API key: %w", err)
	}

	key := model.ApiKey{
		AppID:        app.ID,
		DeploymentID: deployment.ID,
		AppSlug:      app.AppSlug,
		Name:         name,
		KeyPrefix:    app.KeyPrefix,
		KeySuffix:    keySuffix,
		KeyHash:      keyHash,
		Permissions:  []string{},
		Metadata:     map[string]any{},
		OrgRolePerms: []string{},
		WsRolePerms:  []string{},
		IsActive:     true,
		ExpiresAt:    expiresAt,
	}

	if err := database.Connection.Create(&key).Error; err != nil {
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}

	return &ApiKeyWithSecret{
		ApiKeyInfo: ApiKeyInfo{
			ID:          key.ID,
			Name:        key.Name,
			KeyPrefix:   key.KeyPrefix,
			KeySuffix:   key.KeySuffix,
			Permissions: key.Permissions,
			ExpiresAt:   key.ExpiresAt,
			LastUsedAt:  key.LastUsedAt,
			IsActive:    key.IsActive,
			CreatedAt:   key.CreatedAt,
		},
		Secret: fullKey,
	}, nil
}

func (s *Service) GetKeys(deploymentID uint64, appSlug string, status string, includeInactive bool) ([]ApiKeyInfo, error) {
	baseQuery := database.Connection.
		Table("api_keys k").
		Select("k.*").
		Joins("INNER JOIN api_auth_apps a ON k.app_id = a.id").
		Where("a.deployment_id = ? AND a.app_slug = ? AND a.deleted_at IS NULL", deploymentID, appSlug)

	normalizedStatus := strings.ToLower(strings.TrimSpace(status))
	if normalizedStatus == "" {
		if includeInactive {
			normalizedStatus = "all"
		} else {
			normalizedStatus = "active"
		}
	}

	switch normalizedStatus {
	case "active":
		baseQuery = baseQuery.Where("k.is_active = ? AND k.revoked_at IS NULL", true)
	case "revoked":
		baseQuery = baseQuery.Where("k.is_active = ? OR k.revoked_at IS NOT NULL", false)
	case "expired":
		baseQuery = baseQuery.Where("k.expires_at IS NOT NULL AND k.expires_at < ?", time.Now())
	case "all":
	default:
		return nil, fmt.Errorf("invalid status filter: %s", status)
	}

	var keys []model.ApiKey
	err := baseQuery.Order("k.created_at DESC").Find(&keys).Error
	if err != nil {
		return nil, fmt.Errorf("failed to fetch API keys: %w", err)
	}

	if len(keys) == 0 {
		var app model.ApiAuthApp
		if err := database.Connection.
			Where("deployment_id = ? AND app_slug = ?", deploymentID, appSlug).
			First(&app).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return nil, fmt.Errorf("API auth app not found")
			}
			return nil, fmt.Errorf("failed to fetch API auth app: %w", err)
		}
	}

	result := make([]ApiKeyInfo, len(keys))
	for i, key := range keys {
		result[i] = ApiKeyInfo{
			ID:            key.ID,
			Name:          key.Name,
			KeyPrefix:     key.KeyPrefix,
			KeySuffix:     key.KeySuffix,
			Permissions:   key.Permissions,
			ExpiresAt:     key.ExpiresAt,
			LastUsedAt:    key.LastUsedAt,
			IsActive:      key.IsActive,
			CreatedAt:     key.CreatedAt,
			RevokedAt:     key.RevokedAt,
			RevokedReason: key.RevokedReason,
		}
	}

	return result, nil
}

func (s *Service) RotateKey(deployment model.Deployment, appSlug string, keyID uint64) (*ApiKeyWithSecret, error) {
	var existing model.ApiKey
	err := database.Connection.
		Table("api_keys k").
		Joins("INNER JOIN api_auth_apps a ON k.app_id = a.id").
		Where("k.id = ? AND a.deployment_id = ? AND a.app_slug = ? AND a.deleted_at IS NULL AND k.is_active = true AND k.revoked_at IS NULL",
			keyID, deployment.ID, appSlug).
		First(&existing).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("API key not found or inactive")
		}
		return nil, fmt.Errorf("failed to fetch API key: %w", err)
	}

	app, err := s.GetApiAuthApp(deployment.ID, appSlug)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch API auth app: %w", err)
	}

	tx := database.Connection.Begin()
	if tx.Error != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", tx.Error)
	}

	now := time.Now()
	if err := tx.Model(&model.ApiKey{}).
		Where("id = ?", existing.ID).
		Updates(map[string]any{
			"is_active":      false,
			"revoked_at":     &now,
			"revoked_reason": "Rotated",
			"updated_at":     now,
		}).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to revoke old key: %w", err)
	}

	fullKey, keyHash, keySuffix, err := generateApiKey(app.KeyPrefix)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to generate API key: %w", err)
	}

	newKey := model.ApiKey{
		AppID:        existing.AppID,
		DeploymentID: deployment.ID,
		AppSlug:      existing.AppSlug,
		Name:         existing.Name,
		KeyPrefix:    app.KeyPrefix,
		KeySuffix:    keySuffix,
		KeyHash:      keyHash,
		Permissions:  existing.Permissions,
		Metadata:     existing.Metadata,
		OrgRolePerms: existing.OrgRolePerms,
		WsRolePerms:  existing.WsRolePerms,
		OrgID:        existing.OrgID,
		WorkspaceID:  existing.WorkspaceID,
		OrgMemberID:  existing.OrgMemberID,
		WsMemberID:   existing.WsMemberID,
		ExpiresAt:    existing.ExpiresAt,
		IsActive:     true,
	}

	if err := tx.Create(&newKey).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to create rotated key: %w", err)
	}

	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("failed to commit rotation: %w", err)
	}

	return &ApiKeyWithSecret{
		ApiKeyInfo: ApiKeyInfo{
			ID:          newKey.ID,
			Name:        newKey.Name,
			KeyPrefix:   newKey.KeyPrefix,
			KeySuffix:   newKey.KeySuffix,
			Permissions: newKey.Permissions,
			ExpiresAt:   newKey.ExpiresAt,
			LastUsedAt:  newKey.LastUsedAt,
			IsActive:    newKey.IsActive,
			CreatedAt:   newKey.CreatedAt,
		},
		Secret: fullKey,
	}, nil
}

func (s *Service) RevokeKey(deploymentID uint64, appSlug string, keyID uint64, reason string) error {
	var key model.ApiKey
	err := database.Connection.
		Table("api_keys k").
		Joins("INNER JOIN api_auth_apps a ON k.app_id = a.id").
		Where("k.id = ? AND a.deployment_id = ? AND a.app_slug = ? AND a.deleted_at IS NULL",
			keyID, deploymentID, appSlug).
		First(&key).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return fmt.Errorf("API key not found")
		}
		return fmt.Errorf("failed to fetch API key: %w", err)
	}

	now := time.Now()
	updates := map[string]any{
		"is_active":  false,
		"revoked_at": &now,
		"updated_at": now,
	}
	if reason != "" {
		updates["revoked_reason"] = reason
	}

	if err := database.Connection.Model(&model.ApiKey{}).Where("id = ?", key.ID).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to revoke API key: %w", err)
	}

	return nil
}

type AuditLogsResponse struct {
	Data       []model.ApiAuditLog `json:"data"`
	Limit      int                 `json:"limit"`
	HasMore    bool                `json:"has_more"`
	NextCursor string              `json:"next_cursor,omitempty"`
}

func (s *Service) GetAuditLogs(deploymentID uint64, appSlug string, limit int, offset int, cursorTS *time.Time, cursorID string, outcome, keyID, startDate, endDate string) (*AuditLogsResponse, error) {
	ctx := context.Background()
	parsedKeyID, err := parseOptionalInt64String(keyID, "key_id")
	if err != nil {
		return nil, err
	}
	startDateTime, err := parseAuditDateTime(startDate)
	if err != nil {
		return nil, err
	}
	endDateTime, err := parseAuditDateTime(endDate)
	if err != nil {
		return nil, err
	}
	whereParts := []string{"deployment_id = ?", "app_slug = ?"}
	whereArgs := []any{deploymentID, appSlug}

	if outcome != "" && (outcome == "allowed" || outcome == "blocked") {
		if outcome == "allowed" {
			whereParts = append(whereParts, "outcome IN ('allowed','ALLOWED','VALID')")
		} else {
			whereParts = append(whereParts, "outcome IN ('blocked','BLOCKED','RATE_LIMITED')")
		}
	}

	if parsedKeyID != nil {
		whereParts = append(whereParts, "key_id = ?")
		whereArgs = append(whereArgs, *parsedKeyID)
	}

	if startDateTime != nil {
		whereParts = append(whereParts, "timestamp >= ?")
		whereArgs = append(whereArgs, *startDateTime)
		if endDateTime != nil {
			whereParts = append(whereParts, "timestamp <= ?")
			whereArgs = append(whereArgs, *endDateTime)
		}
	} else {
		whereParts = append(whereParts, "timestamp >= now() - INTERVAL 7 DAY")
	}

	if cursorTS != nil {
		cursorTime := cursorTS.UTC()
		if cursorID != "" {
			whereParts = append(whereParts, "(timestamp < ? OR (timestamp = ? AND request_id < ?))")
			whereArgs = append(whereArgs, cursorTime, cursorTime, cursorID)
		} else {
			whereParts = append(whereParts, "timestamp < ?")
			whereArgs = append(whereArgs, cursorTime)
		}
	}

	whereClause := strings.Join(whereParts, " AND ")

	query := fmt.Sprintf(
		"SELECT request_id, deployment_id, app_slug, key_id, key_name, outcome, blocked_by_rule, "+
			"client_ip, path, user_agent, rate_limits, timestamp "+
			"FROM api_audit_logs WHERE %s ORDER BY timestamp DESC, request_id DESC LIMIT %d",
		whereClause, limit+1,
	)
	if cursorTS == nil {
		query += fmt.Sprintf(" OFFSET %d", offset)
	}

	rows, err := database.ClickHouseClient.Query(ctx, query, whereArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch audit logs: %w", err)
	}
	defer rows.Close()

	logs := make([]model.ApiAuditLog, 0)
	for rows.Next() {
		var log model.ApiAuditLog
		err := rows.Scan(
			&log.RequestID,
			&log.DeploymentID,
			&log.AppSlug,
			&log.KeyID,
			&log.KeyName,
			&log.Outcome,
			&log.BlockedByRule,
			&log.ClientIP,
			&log.Path,
			&log.UserAgent,
			&log.RateLimits,
			&log.Timestamp,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}
		logs = append(logs, log)
	}

	hasMore := false
	var nextCursor string
	if len(logs) > limit {
		hasMore = true
		last := logs[limit-1]
		nextCursor = encodeAuditLogCursor(last.Timestamp, last.RequestID)
		logs = logs[:limit]
	} else if len(logs) > 0 {
		last := logs[len(logs)-1]
		nextCursor = encodeAuditLogCursor(last.Timestamp, last.RequestID)
	}

	return &AuditLogsResponse{
		Data:       logs,
		Limit:      limit,
		HasMore:    hasMore,
		NextCursor: nextCursor,
	}, nil
}

type AuditAnalyticsResponse struct {
	TotalRequests   uint64              `json:"total_requests"`
	AllowedRequests uint64              `json:"allowed_requests"`
	BlockedRequests uint64              `json:"blocked_requests"`
	SuccessRate     float64             `json:"success_rate"`
	KeysUsed24h     uint64              `json:"keys_used_24h"`
	TopKeys         []KeyStatsItem      `json:"top_keys,omitempty"`
	TopPaths        []PathStatsItem     `json:"top_paths,omitempty"`
	BlockedReasons  []BlockedReasonItem `json:"blocked_reasons,omitempty"`
	RateLimitStats  *RateLimitBreakdown `json:"rate_limit_stats,omitempty"`
}

type KeyStatsItem struct {
	KeyID         int64  `json:"key_id"`
	KeyName       string `json:"key_name"`
	TotalRequests int64  `json:"total_requests"`
}

type PathStatsItem struct {
	Path          string `json:"path"`
	TotalRequests int64  `json:"total_requests"`
}

type BlockedReasonItem struct {
	BlockedByRule string  `json:"blocked_by_rule"`
	Count         int64   `json:"count"`
	Percentage    float64 `json:"percentage"`
}

type RateLimitBreakdown struct {
	TotalHits  int64                `json:"total_hits"`
	Percentage float64              `json:"percentage_of_blocked"`
	TopRules   []RateLimitStatsItem `json:"top_rules,omitempty"`
}

type RateLimitStatsItem struct {
	Rule       string  `json:"rule"`
	HitCount   int64   `json:"hit_count"`
	Percentage float64 `json:"percentage"`
}

func (s *Service) GetAuditAnalytics(deploymentID uint64, appSlug string, startDate, endDate, keyID string, includeTopKeys, includeTopPaths, includeBlockedReasons, includeRateLimits bool, topLimit int) (*AuditAnalyticsResponse, error) {
	ctx := context.Background()
	parsedKeyID, err := parseOptionalInt64String(keyID, "key_id")
	if err != nil {
		return nil, err
	}
	startDateTime, err := parseAuditDateTime(startDate)
	if err != nil {
		return nil, err
	}
	endDateTime, err := parseAuditDateTime(endDate)
	if err != nil {
		return nil, err
	}

	whereParts := []string{"deployment_id = ?", "app_slug = ?"}
	whereArgs := []any{deploymentID, appSlug}

	if parsedKeyID != nil {
		whereParts = append(whereParts, "key_id = ?")
		whereArgs = append(whereArgs, *parsedKeyID)
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

	// Main analytics query
	query := fmt.Sprintf(
		"SELECT "+
			"count() as total_requests, "+
			"countIf(outcome IN ('allowed','ALLOWED','VALID')) as allowed_requests, "+
			"countIf(outcome IN ('blocked','BLOCKED','RATE_LIMITED')) as blocked_requests "+
			"FROM api_audit_logs WHERE %s",
		whereClause,
	)

	var stats model.ApiAuditStatsRow
	err = database.ClickHouseClient.QueryRow(ctx, query, whereArgs...).Scan(
		&stats.TotalRequests,
		&stats.AllowedRequests,
		&stats.BlockedRequests,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch audit analytics: %w", err)
	}

	successRate := 0.0
	if stats.TotalRequests > 0 {
		successRate = float64(stats.AllowedRequests) / float64(stats.TotalRequests) * 100.0
	}

	keysUsed24h, err := s.fetchKeysUsedLast24h(ctx, deploymentID, appSlug)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch keys used in last 24 hours: %w", err)
	}

	response := &AuditAnalyticsResponse{
		TotalRequests:   stats.TotalRequests,
		AllowedRequests: stats.AllowedRequests,
		BlockedRequests: stats.BlockedRequests,
		SuccessRate:     successRate,
		KeysUsed24h:     keysUsed24h,
	}

	if includeTopKeys {
		topKeys := s.fetchTopKeys(ctx, whereClause, whereArgs, topLimit)
		response.TopKeys = topKeys
	}

	if includeTopPaths {
		topPaths := s.fetchTopPaths(ctx, whereClause, whereArgs, topLimit)
		response.TopPaths = topPaths
	}

	if includeBlockedReasons {
		blockedReasons := s.fetchBlockedReasons(ctx, whereClause, whereArgs, topLimit)
		response.BlockedReasons = blockedReasons
	}

	if includeRateLimits {
		rateLimitStats := s.fetchRateLimitStats(ctx, whereClause, whereArgs, stats.BlockedRequests, topLimit)
		response.RateLimitStats = rateLimitStats
	}

	return response, nil
}

func (s *Service) fetchTopKeys(ctx context.Context, whereClause string, whereArgs []any, limit int) []KeyStatsItem {
	query := fmt.Sprintf(
		"SELECT "+
			"key_id, "+
			"any(key_name) as key_name, "+
			"toInt64(count()) as total_requests "+
			"FROM api_audit_logs "+
			"WHERE %s "+
			"GROUP BY key_id "+
			"ORDER BY total_requests DESC "+
			"LIMIT %d",
		whereClause, limit,
	)

	rows, err := database.ClickHouseClient.Query(ctx, query, whereArgs...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var items []KeyStatsItem
	for rows.Next() {
		var item KeyStatsItem
		if err := rows.Scan(&item.KeyID, &item.KeyName, &item.TotalRequests); err != nil {
			continue
		}
		items = append(items, item)
	}
	return items
}

func (s *Service) fetchTopPaths(ctx context.Context, whereClause string, whereArgs []any, limit int) []PathStatsItem {
	query := fmt.Sprintf(
		"SELECT "+
			"path, "+
			"toInt64(count()) as total_requests "+
			"FROM api_audit_logs "+
			"WHERE %s "+
			"GROUP BY path "+
			"ORDER BY total_requests DESC "+
			"LIMIT %d",
		whereClause, limit,
	)

	rows, err := database.ClickHouseClient.Query(ctx, query, whereArgs...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var items []PathStatsItem
	for rows.Next() {
		var item PathStatsItem
		if err := rows.Scan(&item.Path, &item.TotalRequests); err != nil {
			continue
		}
		items = append(items, item)
	}
	return items
}

func (s *Service) fetchBlockedReasons(ctx context.Context, whereClause string, whereArgs []any, limit int) []BlockedReasonItem {
	blockedWhere := whereClause + " AND outcome IN ('blocked','BLOCKED','RATE_LIMITED') AND blocked_by_rule IS NOT NULL"

	totalQuery := fmt.Sprintf("SELECT count() FROM api_audit_logs WHERE %s", blockedWhere)
	var totalCount int64
	if err := database.ClickHouseClient.QueryRow(ctx, totalQuery, whereArgs...).Scan(&totalCount); err != nil {
		return nil
	}

	query := fmt.Sprintf(
		"SELECT "+
			"blocked_by_rule, "+
			"toInt64(count()) as count "+
			"FROM api_audit_logs "+
			"WHERE %s "+
			"GROUP BY blocked_by_rule "+
			"ORDER BY count DESC "+
			"LIMIT %d",
		blockedWhere, limit,
	)

	rows, err := database.ClickHouseClient.Query(ctx, query, whereArgs...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var items []BlockedReasonItem
	for rows.Next() {
		var item BlockedReasonItem
		if err := rows.Scan(&item.BlockedByRule, &item.Count); err != nil {
			continue
		}
		if totalCount > 0 {
			item.Percentage = float64(item.Count) / float64(totalCount) * 100.0
		}
		items = append(items, item)
	}
	return items
}

func (s *Service) fetchRateLimitStats(ctx context.Context, whereClause string, whereArgs []any, totalBlocked uint64, limit int) *RateLimitBreakdown {
	rlWhere := whereClause + " AND outcome IN ('blocked','BLOCKED','RATE_LIMITED') AND blocked_by_rule LIKE 'rate_limit:%'"

	totalQuery := fmt.Sprintf("SELECT count() FROM api_audit_logs WHERE %s", rlWhere)
	var totalHits int64
	if err := database.ClickHouseClient.QueryRow(ctx, totalQuery, whereArgs...).Scan(&totalHits); err != nil {
		return nil
	}

	query := fmt.Sprintf(
		"SELECT "+
			"blocked_by_rule as rule, "+
			"toInt64(count()) as hit_count "+
			"FROM api_audit_logs "+
			"WHERE %s "+
			"GROUP BY rule "+
			"ORDER BY hit_count DESC "+
			"LIMIT %d",
		rlWhere, limit,
	)

	rows, err := database.ClickHouseClient.Query(ctx, query, whereArgs...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var topRules []RateLimitStatsItem
	for rows.Next() {
		var item RateLimitStatsItem
		if err := rows.Scan(&item.Rule, &item.HitCount); err != nil {
			continue
		}
		if totalHits > 0 {
			item.Percentage = float64(item.HitCount) / float64(totalHits) * 100.0
		}
		topRules = append(topRules, item)
	}

	percentage := 0.0
	if totalBlocked > 0 {
		percentage = float64(totalHits) / float64(totalBlocked) * 100.0
	}

	return &RateLimitBreakdown{
		TotalHits:  totalHits,
		Percentage: percentage,
		TopRules:   topRules,
	}
}

func (s *Service) fetchKeysUsedLast24h(ctx context.Context, deploymentID uint64, appSlug string) (uint64, error) {
	query := "SELECT countDistinct(key_id) FROM api_audit_logs WHERE deployment_id = ? AND app_slug = ? AND timestamp >= now() - INTERVAL 24 HOUR"

	var total uint64
	if err := database.ClickHouseClient.QueryRow(ctx, query, deploymentID, appSlug).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

type AuditTimeseriesPoint struct {
	Timestamp       time.Time `json:"timestamp"`
	TotalRequests   int64     `json:"total_requests"`
	AllowedRequests int64     `json:"allowed_requests"`
	BlockedRequests int64     `json:"blocked_requests"`
	SuccessRate     float64   `json:"success_rate"`
}

type AuditTimeseriesResponse struct {
	Data     []AuditTimeseriesPoint `json:"data"`
	Interval string                 `json:"interval"`
}

func (s *Service) GetAuditTimeseries(deploymentID uint64, appSlug string, startDate, endDate, interval, keyID string) (*AuditTimeseriesResponse, error) {
	ctx := context.Background()
	parsedKeyID, err := parseOptionalInt64String(keyID, "key_id")
	if err != nil {
		return nil, err
	}
	startDateTime, err := parseAuditDateTime(startDate)
	if err != nil {
		return nil, err
	}
	endDateTime, err := parseAuditDateTime(endDate)
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

	if parsedKeyID != nil {
		whereParts = append(whereParts, "key_id = ?")
		whereArgs = append(whereArgs, *parsedKeyID)
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

	query := fmt.Sprintf(
		"SELECT "+
			"%s(timestamp) as bucket, "+
			"toInt64(count()) as total_requests, "+
			"toInt64(countIf(outcome IN ('allowed','ALLOWED','VALID'))) as allowed_requests, "+
			"toInt64(countIf(outcome IN ('blocked','BLOCKED','RATE_LIMITED'))) as blocked_requests "+
			"FROM api_audit_logs "+
			"WHERE %s "+
			"GROUP BY bucket ORDER BY bucket ASC",
		intervalFunc, whereClause,
	)

	rows, err := database.ClickHouseClient.Query(ctx, query, whereArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch audit timeseries: %w", err)
	}
	defer rows.Close()

	var points []AuditTimeseriesPoint
	for rows.Next() {
		var row model.ApiAuditTimeseriesRow
		err := rows.Scan(
			&row.Bucket,
			&row.TotalRequests,
			&row.AllowedRequests,
			&row.BlockedRequests,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan timeseries: %w", err)
		}

		successRate := 0.0
		if row.TotalRequests > 0 {
			successRate = float64(row.AllowedRequests) / float64(row.TotalRequests) * 100.0
		}

		points = append(points, AuditTimeseriesPoint{
			Timestamp:       row.Bucket,
			TotalRequests:   row.TotalRequests,
			AllowedRequests: row.AllowedRequests,
			BlockedRequests: row.BlockedRequests,
			SuccessRate:     successRate,
		})
	}

	return &AuditTimeseriesResponse{
		Data:     points,
		Interval: interval,
	}, nil
}

func generateApiKey(prefix string) (string, string, string, error) {
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", "", err
	}

	secret := base64.RawURLEncoding.EncodeToString(randomBytes)
	fullKey := fmt.Sprintf("%s_%s", prefix, secret)

	hash := sha256.Sum256([]byte(fullKey))
	keyHash := hex.EncodeToString(hash[:])

	if len(fullKey) < 8 {
		return "", "", "", fmt.Errorf("invalid api key length")
	}
	keySuffix := fullKey[len(fullKey)-8:]

	return fullKey, keyHash, keySuffix, nil
}

func encodeAuditLogCursor(ts time.Time, requestID string) string {
	payload := fmt.Sprintf("%d|%s", ts.UTC().UnixMilli(), requestID)
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

func parseOptionalInt64String(value string, field string) (*int64, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid %s", field)
	}
	return &parsed, nil
}

func parseAuditDateTime(value string) (*time.Time, error) {
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
	return nil, fmt.Errorf("invalid date format")
}
