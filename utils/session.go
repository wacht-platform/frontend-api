package utils

import (
	"fmt"
	"log"
	"strconv"

	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
)

func GetSessionByID(sessionID uint64) (*model.Session, error) {
	session := new(model.Session)

	query := `
	SELECT
		s.id,
		s.created_at,
		s.updated_at,
		s.active_signin_id,

		-- Active Signin Data
		asi.id as "ActiveSignin__id",
		asi.created_at as "ActiveSignin__created_at",
		asi.updated_at as "ActiveSignin__updated_at",
		asi.user_id as "ActiveSignin__user_id",
		asi.session_id as "ActiveSignin__session_id",
		asi.active_organization_membership_id as "ActiveSignin__active_organization_membership_id",
		asi.active_workspace_membership_id as "ActiveSignin__active_workspace_membership_id",
		asi.expires_at as "ActiveSignin__expires_at",
		asi.last_active_at as "ActiveSignin__last_active_at",
		asi.ip_address as "ActiveSignin__ip_address",
		asi.browser as "ActiveSignin__browser",
		asi.device as "ActiveSignin__device",
		asi.city as "ActiveSignin__city",
		asi.region as "ActiveSignin__region",
		asi.region_code as "ActiveSignin__region_code",
		asi.country as "ActiveSignin__country",
		asi.country_code as "ActiveSignin__country_code",

		-- Active User Data
		au.id as "ActiveSignin__User__id",
		au.created_at as "ActiveSignin__User__created_at",
		au.updated_at as "ActiveSignin__User__updated_at",
		au.first_name as "ActiveSignin__User__first_name",
		au.last_name as "ActiveSignin__User__last_name",
		au.username as "ActiveSignin__User__username",
		au.has_profile_picture as "ActiveSignin__User__has_profile_picture",
		au.profile_picture_url as "ActiveSignin__User__profile_picture_url",
		au.availability as "ActiveSignin__User__availability",
		au.last_password_reset_at as "ActiveSignin__User__last_password_reset_at",
		au.schema_version as "ActiveSignin__User__schema_version",
		au.disabled as "ActiveSignin__User__disabled",
		au.primary_email_address_id as "ActiveSignin__User__primary_email_address_id",
		au.primary_phone_number_id as "ActiveSignin__User__primary_phone_number_id",
		au.second_factor_policy as "ActiveSignin__User__second_factor_policy",
		au.active_organization_membership_id as "ActiveSignin__User__active_organization_membership_id",
		au.active_workspace_membership_id as "ActiveSignin__User__active_workspace_membership_id",
		au.public_metadata as "ActiveSignin__User__public_metadata",
		au.backup_codes_generated as "ActiveSignin__User__backup_codes_generated",

		-- Organization Membership
		aom.id as "ActiveSignin__ActiveOrganizationMembership__id",
		aom.organization_id as "ActiveSignin__ActiveOrganizationMembership__organization_id",
		aom.user_id as "ActiveSignin__ActiveOrganizationMembership__user_id",

		-- Workspace Membership
		awm.id as "ActiveSignin__ActiveWorkspaceMembership__id",
		awm.workspace_id as "ActiveSignin__ActiveWorkspaceMembership__workspace_id",
		awm.user_id as "ActiveSignin__ActiveWorkspaceMembership__user_id",
		awm.organization_membership_id as "ActiveSignin__ActiveWorkspaceMembership__organization_membership_id"

	FROM sessions s
	LEFT JOIN signins asi ON s.active_signin_id = asi.id
	LEFT JOIN users au ON asi.user_id = au.id
	LEFT JOIN organization_memberships aom ON asi.active_organization_membership_id = aom.id
	LEFT JOIN workspace_memberships awm ON asi.active_workspace_membership_id = awm.id
	WHERE s.id = ? AND s.deleted_at IS NULL`

	err := database.Connection.Raw(query, sessionID).Scan(session).Error
	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	if session.ActiveSignin != nil && session.ActiveSignin.User != nil {
		database.Connection.Where("user_id = ?", session.ActiveSignin.User.ID).Find(&session.ActiveSignin.User.UserEmailAddresses)
		database.Connection.Where("user_id = ?", session.ActiveSignin.User.ID).Find(&session.ActiveSignin.User.UserPhoneNumbers)
		database.Connection.Where("user_id = ?", session.ActiveSignin.User.ID).Find(&session.ActiveSignin.User.SocialConnections)
	}

	database.Connection.Where("session_id = ?", sessionID).Find(&session.SigninAttempts)
	database.Connection.Where("session_id = ?", sessionID).Find(&session.SignupAttempts)
	database.Connection.Preload("User.UserEmailAddresses").Preload("User.UserPhoneNumbers").Preload("User.SocialConnections").Where("session_id = ?", sessionID).Find(&session.Signins)

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
