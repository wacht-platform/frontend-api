package model

import (
	"time"

	"github.com/ilabs/wacht-fe/pkg/idgen"
	"gorm.io/gorm"
)

type Signin struct {
	Model
	SessionID                      uint64                  `json:"session_id,string"                        gorm:"index"`
	UserID                         *uint64                 `json:"user_id,string"                           gorm:"index"`
	ActiveOrganizationMembershipID *uint64                 `json:"active_organization_membership_id,string"`
	ActiveWorkspaceMembershipID    *uint64                 `json:"active_workspace_membership_id,string"`
	User                           *User                   `json:"user,omitempty"                           gorm:"foreignKey:UserID"`
	ActiveWorkspaceMembership      *WorkspaceMembership    `json:"active_workspace_membership,omitempty"`
	ActiveOrganizationMembership   *OrganizationMembership `json:"active_organization_membership,omitempty"`
	ExpiresAt                      time.Time               `json:"expires_at"                               gorm:"not null"`
	LastActiveAt                   time.Time               `json:"last_active_at"                           gorm:"not null"`
	IpAddress                      string                  `json:"ip_address"`
	Browser                        string                  `json:"browser"`
	Device                         string                  `json:"device"`
	City                           string                  `json:"city"`
	Region                         string                  `json:"region"`
	RegionCode                     string                  `json:"region_code"`
	Country                        string                  `json:"country"`
	CountryCode                    string                  `json:"country_code"`
}

func NewSignIn(sessionID, userID uint64, validityPeriodSeconds uint64) *Signin {
	now := time.Now()
	return &Signin{
		Model: Model{
			ID: idgen.NextID(),
		},
		SessionID:    sessionID,
		UserID:       &userID,
		ExpiresAt:    now.Add(time.Duration(validityPeriodSeconds) * time.Second),
		LastActiveAt: now,
	}
}

func (s *Signin) LoadUser(db *gorm.DB) {
	db.Preload("User").First(s)
}
