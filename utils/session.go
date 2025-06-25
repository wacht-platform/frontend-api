package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"

	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
)



func GetSessionByID(sessionID uint64) (*model.Session, error) {
	cacheKey := "session:" + strconv.FormatUint(sessionID, 10)

	cacheData, err := GetMultipleFromCache(cacheKey)
	if err == nil {
		if sessionData, exists := cacheData[cacheKey]; exists {
			sessionBytes, _ := json.Marshal(sessionData)
			session := new(model.Session)
			if json.Unmarshal(sessionBytes, session) == nil {
				return session, nil
			}
		}
	}

	session := new(model.Session)

	// Single query using JOINs to get session with active signin and all required data
	err = database.Connection.
		Joins("LEFT JOIN signins active_signin ON sessions.active_signin_id = active_signin.id").
		Joins("LEFT JOIN users active_user ON active_signin.user_id = active_user.id").
		Joins("LEFT JOIN organization_memberships active_org_mem ON active_signin.active_organization_membership_id = active_org_mem.id").
		Joins("LEFT JOIN workspace_memberships active_ws_mem ON active_signin.active_workspace_membership_id = active_ws_mem.id").
		Select(`
			sessions.*,
			active_signin.id as "ActiveSignin__id",
			active_signin.created_at as "ActiveSignin__created_at",
			active_signin.updated_at as "ActiveSignin__updated_at",
			active_signin.user_id as "ActiveSignin__user_id",
			active_signin.session_id as "ActiveSignin__session_id",
			active_signin.active_organization_membership_id as "ActiveSignin__active_organization_membership_id",
			active_signin.active_workspace_membership_id as "ActiveSignin__active_workspace_membership_id",
			active_signin.expires_at as "ActiveSignin__expires_at",
			active_signin.last_active_at as "ActiveSignin__last_active_at",
			active_signin.ip_address as "ActiveSignin__ip_address",
			active_signin.browser as "ActiveSignin__browser",
			active_signin.device as "ActiveSignin__device",
			active_signin.city as "ActiveSignin__city",
			active_signin.region as "ActiveSignin__region",
			active_signin.region_code as "ActiveSignin__region_code",
			active_signin.country as "ActiveSignin__country",
			active_signin.country_code as "ActiveSignin__country_code",
			active_user.id as "ActiveSignin__User__id",
			active_user.created_at as "ActiveSignin__User__created_at",
			active_user.updated_at as "ActiveSignin__User__updated_at",
			active_user.first_name as "ActiveSignin__User__first_name",
			active_user.last_name as "ActiveSignin__User__last_name",
			active_user.username as "ActiveSignin__User__username",
			active_user.has_profile_picture as "ActiveSignin__User__has_profile_picture",
			active_user.profile_picture_url as "ActiveSignin__User__profile_picture_url",
			active_user.availability as "ActiveSignin__User__availability",
			active_user.last_password_reset_at as "ActiveSignin__User__last_password_reset_at",
			active_user.schema_version as "ActiveSignin__User__schema_version",
			active_user.disabled as "ActiveSignin__User__disabled",
			active_user.primary_email_address_id as "ActiveSignin__User__primary_email_address_id",
			active_user.primary_phone_number_id as "ActiveSignin__User__primary_phone_number_id",
			active_user.second_factor_policy as "ActiveSignin__User__second_factor_policy",
			active_user.active_organization_membership_id as "ActiveSignin__User__active_organization_membership_id",
			active_user.active_workspace_membership_id as "ActiveSignin__User__active_workspace_membership_id",
			active_user.public_metadata as "ActiveSignin__User__public_metadata",
			active_user.backup_codes_generated as "ActiveSignin__User__backup_codes_generated",
			active_org_mem.id as "ActiveSignin__ActiveOrganizationMembership__id",
			active_org_mem.organization_id as "ActiveSignin__ActiveOrganizationMembership__organization_id",
			active_org_mem.user_id as "ActiveSignin__ActiveOrganizationMembership__user_id",
			active_ws_mem.id as "ActiveSignin__ActiveWorkspaceMembership__id",
			active_ws_mem.workspace_id as "ActiveSignin__ActiveWorkspaceMembership__workspace_id",
			active_ws_mem.user_id as "ActiveSignin__ActiveWorkspaceMembership__user_id",
			active_ws_mem.organization_membership_id as "ActiveSignin__ActiveWorkspaceMembership__organization_membership_id"
		`).
		Where("sessions.id = ? AND sessions.deleted_at IS NULL", sessionID).
		First(session).Error

	if err != nil {
		return nil, fmt.Errorf("session not found")
	}

	database.Connection.Where("session_id = ?", sessionID).Find(&session.SigninAttempts)

	database.Connection.Where("session_id = ?", sessionID).Find(&session.SignupAttempts)

	database.Connection.
		Joins("LEFT JOIN users ON signins.user_id = users.id").
		Where("signins.session_id = ?", sessionID).
		Find(&session.Signins)

	if session.ActiveSignin != nil && session.ActiveSignin.ActiveOrganizationMembershipID != nil {
		var orgRoles []*model.OrganizationRole
		database.Connection.
			Joins("JOIN organization_membership_roles ON organization_roles.id = organization_membership_roles.organization_role_id").
			Where("organization_membership_roles.organization_membership_id = ?", *session.ActiveSignin.ActiveOrganizationMembershipID).
			Find(&orgRoles)

		if session.ActiveSignin.ActiveOrganizationMembership == nil {
			session.ActiveSignin.ActiveOrganizationMembership = &model.OrganizationMembership{}
		}
		session.ActiveSignin.ActiveOrganizationMembership.Roles = orgRoles
	}

	if session.ActiveSignin != nil && session.ActiveSignin.ActiveWorkspaceMembershipID != nil {
		var wsRoles []*model.WorkspaceRole
		database.Connection.
			Joins("JOIN workspace_membership_roles ON workspace_roles.id = workspace_membership_roles.workspace_role_id").
			Where("workspace_membership_roles.workspace_membership_id = ?", *session.ActiveSignin.ActiveWorkspaceMembershipID).
			Find(&wsRoles)

		if session.ActiveSignin.ActiveWorkspaceMembership == nil {
			session.ActiveSignin.ActiveWorkspaceMembership = &model.WorkspaceMembership{}
		}
		session.ActiveSignin.ActiveWorkspaceMembership.Roles = wsRoles
	}

	go setSessionCache(*session)

	return session, nil
}

func setSessionCache(session model.Session) {
	cacheKey := "session:" + strconv.FormatUint(session.ID, 10)
	err := SetToCache(cacheKey, session, 3600)
	if err != nil {
		log.Println("Error setting session cache: ", err)
	}
}
