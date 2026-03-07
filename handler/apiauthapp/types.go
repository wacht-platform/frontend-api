package apiauthapp

import (
	"time"

	"github.com/wacht-platform/frontend-api/model"
)

// ApiAuthAppInfo represents API auth app info for responses
type ApiAuthAppInfo struct {
	AppSlug     string      `json:"app_slug"`
	Name        string      `json:"name"`
	KeyPrefix   string      `json:"key_prefix"`
	Description *string     `json:"description,omitempty"`
	IsActive    bool        `json:"is_active"`
	RateLimits  []RateLimit `json:"rate_limits"`
}

type RateLimit struct {
	Unit        string  `json:"unit"`
	Duration    int32   `json:"duration"`
	MaxRequests int32   `json:"max_requests"`
	Mode        *string `json:"mode,omitempty"`
}

type ApiKeyInfo struct {
	ID            uint64     `json:"id,string"`
	Name          string     `json:"name"`
	KeyPrefix     string     `json:"key_prefix"`
	KeySuffix     string     `json:"key_suffix"`
	Permissions   []string   `json:"permissions"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
	IsActive      bool       `json:"is_active"`
	CreatedAt     time.Time  `json:"created_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokedReason *string    `json:"revoked_reason,omitempty"`
}

type ApiKeyWithSecret struct {
	ApiKeyInfo
	Secret string `json:"secret"`
}

func convertRateLimits(limits model.RateLimits) []RateLimit {
	result := make([]RateLimit, len(limits))
	for i, limit := range limits {
		var mode *string
		if limit.Mode != nil {
			m := string(*limit.Mode)
			mode = &m
		}
		result[i] = RateLimit{
			Unit:        string(limit.Unit),
			Duration:    limit.Duration,
			MaxRequests: limit.MaxRequests,
			Mode:        mode,
		}
	}
	return result
}
