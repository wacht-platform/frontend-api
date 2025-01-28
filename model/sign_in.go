package model

import (
	"github.com/godruoyi/go-snowflake"
)

type SignIn struct {
	Model
	SessionID                uint                 `json:"-"                              gorm:"index:idx_session_user_id,unique"`
	UserID                   uint                 `json:"-"                              gorm:"index:idx_session_user_id,unique"`
	WorkspaceMembershipID    uint                 `json:"-"`
	OrganizationMembershipID uint                 `json:"-"`
	User                     *User                `json:"user,omitempty"`
	OrgMembereship           *OrgMembership       `json:"org_membership,omitempty"`
	WorkspaceMembership      *WorkspaceMembership `json:"workspace_membership,omitempty"`
	Expired                  bool                 `json:"expired"`
	ExpiredAt                string               `json:"expired_at"`
}

func NewSignIn(sessionID, userID uint) *SignIn {
	return &SignIn{
		Model: Model{
			ID: uint(snowflake.ID()),
		},
		SessionID: sessionID,
		UserID:    userID,
		Expired:   false,
	}
}
