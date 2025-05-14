package model

import (
	"github.com/lib/pq"
	"gorm.io/datatypes"
)

type Workspace struct {
	Model
	OrganizationID      uint64                 `json:"-"               gorm:"not null;index;"`
	Name                string                 `json:"name"            gorm:"not null"`
	ImageUrl            string                 `json:"image_url"       gorm:"not null"`
	Description         string                 `json:"description"     gorm:"not null"`
	InviteOnly          bool                   `json:"invite_only"     gorm:"not null;default:true"`
	Roles               []*WorkspaceRole       `json:"roles"`
	Members             []*WorkspaceMembership `json:"members"`
	EnforceMFASetup     bool                   `json:"enforce_2fa" gorm:"not null;default:false"`
	EnableIPRestriction bool                   `json:"enable_ip_restriction" gorm:"not null;default:false"`
	WhitelistedIPs      pq.StringArray         `json:"whitelisted_ips" gorm:"type:text[]"`
	MemberCount         uint64                 `json:"member_count"    gorm:"not null"`
	PublicMetadata      datatypes.JSONMap      `json:"public_metadata" gorm:"not null"`
	PrivateMetadata     datatypes.JSONMap      `json:"-"               gorm:"not null"`
}
