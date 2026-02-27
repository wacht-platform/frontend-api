package model

import (
	"database/sql/driver"
	"encoding/json"
	"time"
)

type RateLimitMode string

const (
	RateLimitModePerKey      RateLimitMode = "per_key"
	RateLimitModePerIp       RateLimitMode = "per_ip"
	RateLimitModePerKeyAndIp RateLimitMode = "per_key_and_ip"
	RateLimitModePerApp      RateLimitMode = "per_app"
	RateLimitModePerAppAndIp RateLimitMode = "per_app_and_ip"
)

type RateLimitUnit string

const (
	RateLimitUnitMillisecond   RateLimitUnit = "millisecond"
	RateLimitUnitSecond        RateLimitUnit = "second"
	RateLimitUnitMinute        RateLimitUnit = "minute"
	RateLimitUnitHour          RateLimitUnit = "hour"
	RateLimitUnitDay           RateLimitUnit = "day"
	RateLimitUnitCalendarDay   RateLimitUnit = "calendar_day"
	RateLimitUnitMonth         RateLimitUnit = "month"
	RateLimitUnitCalendarMonth RateLimitUnit = "calendar_month"
)

type RateLimit struct {
	Unit        RateLimitUnit  `json:"unit"          gorm:"type:varchar(20);not null"`
	Duration    int32          `json:"duration"      gorm:"not null"`
	MaxRequests int32          `json:"max_requests"  gorm:"not null"`
	Mode        *RateLimitMode `json:"mode,omitempty" gorm:"type:varchar(30)"`
	Endpoints   []string       `json:"endpoints,omitempty" gorm:"type:jsonb"`
	Priority    int32          `json:"priority,omitempty" gorm:"default:0"`
}

// RateLimits is a slice of RateLimit that implements sql.Scanner and driver.Valuer
type RateLimits []RateLimit

// Scan implements sql.Scanner for RateLimits
func (rl *RateLimits) Scan(value any) error {
	if value == nil {
		*rl = make(RateLimits, 0)
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, rl)
}

// Value implements driver.Valuer for RateLimits
func (rl RateLimits) Value() (driver.Value, error) {
	if len(rl) == 0 {
		return "[]", nil
	}
	return json.Marshal(rl)
}

type ApiAuthApp struct {
	DeploymentID        uint64     `json:"deployment_id,string"      gorm:"primarykey;index;not null"`
	UserID              *uint64    `json:"user_id,string,omitempty"  gorm:"column:user_id;index"`
	AppSlug             string     `json:"app_slug"                  gorm:"primarykey;type:varchar(255);not null"`
	Name                string     `json:"name"                      gorm:"type:varchar(255);not null"`
	Description         *string    `json:"description,omitempty"     gorm:"type:text"`
	IsActive            bool       `json:"is_active"                 gorm:"not null;default:true"`
	KeyPrefix           string     `json:"key_prefix"                gorm:"type:varchar(64);not null"`
	RateLimits          RateLimits `json:"rate_limits"               gorm:"-"`
	RateLimitSchemeSlug *string    `json:"rate_limit_scheme_slug,omitempty" gorm:"type:varchar(255)"`
	CreatedAt           time.Time  `json:"created_at"                gorm:"autoCreateTime"`
	UpdatedAt           time.Time  `json:"updated_at"                gorm:"autoUpdateTime"`
	DeletedAt           *time.Time `json:"deleted_at,omitempty"      gorm:"index"`
}

// ApiKey represents an API key for authentication
type ApiKey struct {
	ID            uint64         `gorm:"primarykey"                json:"id,string"`
	DeploymentID  uint64         `json:"deployment_id,string"      gorm:"index;not null"`
	OwnerUserID   *uint64        `json:"owner_user_id,string,omitempty"         gorm:"column:owner_user_id;index"`
	AppSlug       string         `json:"app_slug"                  gorm:"column:app_slug;type:varchar(255);not null"`
	Name          string         `json:"name"                      gorm:"type:varchar(255);not null"`
	KeyPrefix     string         `json:"key_prefix"                gorm:"type:varchar(20);not null"`
	KeySuffix     string         `json:"key_suffix"                gorm:"type:varchar(10);not null"`
	KeyHash       string         `json:"-"                         gorm:"type:varchar(128);not null"` // SHA-256 hash
	Permissions   []string       `json:"permissions"               gorm:"type:jsonb;serializer:json;default:'[]'::jsonb"`
	OrgRolePerms  []string       `json:"org_role_permissions"       gorm:"column:org_role_permissions;type:jsonb;serializer:json;default:'[]'::jsonb"`
	WsRolePerms   []string       `json:"workspace_role_permissions" gorm:"column:workspace_role_permissions;type:jsonb;serializer:json;default:'[]'::jsonb"`
	Metadata      map[string]any `json:"metadata"                  gorm:"type:jsonb;serializer:json;default:'{}'::jsonb"`
	RateLimitSchemeSlug *string  `json:"-"                         gorm:"column:rate_limit_scheme_slug;type:varchar(255)"`
	OrgID         *uint64        `json:"organization_id,string,omitempty"         gorm:"column:organization_id;index"`
	WorkspaceID   *uint64        `json:"workspace_id,string,omitempty"            gorm:"column:workspace_id;index"`
	OrgMemberID   *uint64        `json:"organization_membership_id,string,omitempty" gorm:"column:organization_membership_id;index"`
	WsMemberID    *uint64        `json:"workspace_membership_id,string,omitempty"    gorm:"column:workspace_membership_id;index"`
	ExpiresAt     *time.Time     `json:"expires_at,omitempty"`
	LastUsedAt    *time.Time     `json:"last_used_at,omitempty"`
	IsActive      bool           `json:"is_active"                 gorm:"not null;default:true"`
	CreatedAt     time.Time      `json:"created_at"                gorm:"autoCreateTime"`
	UpdatedAt     time.Time      `json:"updated_at"                gorm:"autoUpdateTime"`
	RevokedAt     *time.Time     `json:"revoked_at,omitempty"`
	RevokedReason *string        `json:"revoked_reason,omitempty"  gorm:"type:text"`
}

// RateLimitScheme represents a reusable rate limit configuration
type RateLimitScheme struct {
	ID           uint64     `gorm:"primarykey"                json:"id,string"`
	DeploymentID uint64     `json:"deployment_id,string"      gorm:"index;not null"`
	Slug         string     `json:"slug"                      gorm:"type:varchar(255);not null"`
	Name         string     `json:"name"                      gorm:"type:varchar(255);not null"`
	Description  *string    `json:"description,omitempty"     gorm:"type:text"`
	Rules        RateLimits `json:"rules"                     gorm:"type:jsonb;not null;serializer:json"`
	CreatedAt    time.Time  `json:"created_at"                gorm:"autoCreateTime"`
	UpdatedAt    time.Time  `json:"updated_at"                gorm:"autoUpdateTime"`
}
