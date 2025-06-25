package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"

	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
	"gorm.io/plugin/dbresolver"
)

func GetSessionByID(sessionID uint64) (*model.Session, error) {
	session := new(model.Session)

	mainQuery := `
	WITH session_data AS (
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
			awm.organization_membership_id as "ActiveSignin__ActiveWorkspaceMembership__organization_membership_id",

			-- User Email Addresses (JSON aggregated)
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', ue.id,
						'email_address', ue.email_address,
						'is_primary', ue.is_primary,
						'verified', ue.verified,
						'verified_at', ue.verified_at,
						'verification_strategy', ue.verification_strategy,
						'created_at', ue.created_at,
						'updated_at', ue.updated_at
					) ORDER BY ue.is_primary DESC, ue.created_at
				) FROM user_email_addresses ue WHERE ue.user_id = au.id),
				'[]'::json
			) as user_email_addresses,

			-- User Phone Numbers (JSON aggregated)
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', up.id,
						'phone_number', up.phone_number,
						'verified', up.verified,
						'verified_at', up.verified_at,
						'can_use_for_second_factor', up.can_use_for_second_factor,
						'created_at', up.created_at,
						'updated_at', up.updated_at
					) ORDER BY up.created_at
				) FROM user_phone_numbers up WHERE up.user_id = au.id),
				'[]'::json
			) as user_phone_numbers,

			-- User Social Connections (JSON aggregated)
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', sc.id,
						'provider', sc.provider,
						'user_email_address_id', sc.user_email_address_id,
						'email_address', sc.email_address,
						'first_name', sc.first_name,
						'last_name', sc.last_name,
						'created_at', sc.created_at,
						'updated_at', sc.updated_at
					) ORDER BY sc.created_at
				) FROM social_connections sc WHERE sc.user_id = au.id),
				'[]'::json
			) as user_social_connections,

			-- Signin Attempts (JSON aggregated)
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', sia.id,
						'created_at', sia.created_at,
						'updated_at', sia.updated_at,
						'user_id', sia.user_id,
						'identifier_id', sia.identifier_id,
						'session_id', sia.session_id,
						'method', sia.method,
						'sso_provider', sia.sso_provider,
						'expires_at', sia.expires_at,
						'current_step', sia.current_step,
						'remaining_steps', sia.remaining_steps,
						'completed', sia.completed,
						'errored', sia.errored,
						'errors', sia.errors,
						'requires_completion', sia.requires_completion,
						'missing_fields', sia.missing_fields,
						'required_fields', sia.required_fields
					) ORDER BY sia.created_at DESC
				) FROM sign_in_attempts sia WHERE sia.session_id = s.id),
				'[]'::json
			) as signin_attempts,

			-- Signup Attempts (JSON aggregated)
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', sua.id,
						'created_at', sua.created_at,
						'updated_at', sua.updated_at,
						'session_id', sua.session_id,
						'first_name', sua.first_name,
						'last_name', sua.last_name,
						'email', sua.email,
						'username', sua.username,
						'phone_number', sua.phone_number,
						'required_fields', sua.required_fields,
						'missing_fields', sua.missing_fields,
						'current_step', sua.current_step,
						'remaining_steps', sua.remaining_steps,
						'sso_provider', sua.sso_provider,
						'is_oauth_signup', sua.is_oauth_signup
					) ORDER BY sua.created_at DESC
				) FROM signup_attempts sua WHERE sua.session_id = s.id),
				'[]'::json
			) as signup_attempts,

			-- Organization Roles (JSON aggregated)
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', or_role.id,
						'created_at', or_role.created_at,
						'updated_at', or_role.updated_at,
						'organization_id', or_role.organization_id,
						'name', or_role.name,
						'permissions', or_role.permissions,
						'deployment_id', or_role.deployment_id
					) ORDER BY or_role.name
				) FROM organization_membership_roles omr
				JOIN organization_roles or_role ON omr.organization_role_id = or_role.id
				WHERE omr.organization_membership_id = asi.active_organization_membership_id),
				'[]'::json
			) as organization_roles,

			-- Workspace Roles (JSON aggregated)
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', ws_role.id,
						'created_at', ws_role.created_at,
						'updated_at', ws_role.updated_at,
						'organization_id', ws_role.organization_id,
						'name', ws_role.name,
						'permissions', ws_role.permissions,
						'deployment_id', ws_role.deployment_id,
						'workspace_id', ws_role.workspace_id
					) ORDER BY ws_role.name
				) FROM workspace_membership_roles wmr
				JOIN workspace_roles ws_role ON wmr.workspace_role_id = ws_role.id
				WHERE wmr.workspace_membership_id = asi.active_workspace_membership_id),
				'[]'::json
			) as workspace_roles,

			-- All Signins for Session (JSON aggregated)
			COALESCE(
				(SELECT json_agg(
					json_build_object(
						'id', si.id,
						'created_at', si.created_at,
						'updated_at', si.updated_at,
						'session_id', si.session_id,
						'user_id', si.user_id,
						'active_organization_membership_id', si.active_organization_membership_id,
						'active_workspace_membership_id', si.active_workspace_membership_id,
						'expires_at', si.expires_at,
						'last_active_at', si.last_active_at,
						'ip_address', si.ip_address,
						'browser', si.browser,
						'device', si.device,
						'city', si.city,
						'region', si.region,
						'region_code', si.region_code,
						'country', si.country,
						'country_code', si.country_code,
						'user', json_build_object(
							'id', u.id,
							'created_at', u.created_at,
							'updated_at', u.updated_at,
							'first_name', u.first_name,
							'last_name', u.last_name,
							'username', u.username,
							'has_profile_picture', u.has_profile_picture,
							'profile_picture_url', u.profile_picture_url,
							'availability', u.availability,
							'last_password_reset_at', u.last_password_reset_at,
							'schema_version', u.schema_version,
							'disabled', u.disabled,
							'primary_email_address_id', u.primary_email_address_id,
							'primary_phone_number_id', u.primary_phone_number_id,
							'second_factor_policy', u.second_factor_policy,
							'active_organization_membership_id', u.active_organization_membership_id,
							'active_workspace_membership_id', u.active_workspace_membership_id,
							'public_metadata', u.public_metadata,
							'backup_codes_generated', u.backup_codes_generated
						)
					) ORDER BY si.created_at DESC
				) FROM signins si
				LEFT JOIN users u ON si.user_id = u.id
				WHERE si.session_id = s.id),
				'[]'::json
			) as signins

		FROM sessions s
		LEFT JOIN signins asi ON s.active_signin_id = asi.id
		LEFT JOIN users au ON asi.user_id = au.id
		LEFT JOIN organization_memberships aom ON asi.active_organization_membership_id = aom.id
		LEFT JOIN workspace_memberships awm ON asi.active_workspace_membership_id = awm.id
		WHERE s.id = ? AND s.deleted_at IS NULL
	)
	SELECT * FROM session_data`

	type QueryResult struct {
		model.Session
		UserEmailAddresses    string `json:"user_email_addresses"`
		UserPhoneNumbers      string `json:"user_phone_numbers"`
		UserSocialConnections string `json:"user_social_connections"`
		SigninAttemptsJSON    string `json:"signin_attempts"`
		SignupAttemptsJSON    string `json:"signup_attempts"`
		OrganizationRoles     string `json:"organization_roles"`
		WorkspaceRoles        string `json:"workspace_roles"`
		SigninsJSON           string `json:"signins"`
	}

	var result QueryResult
	err := database.Connection.Clauses(dbresolver.Read).Raw(mainQuery, sessionID).Scan(&result).Error
	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	*session = result.Session

	// Parse JSON data for signins
	if result.SigninsJSON != "" && result.SigninsJSON != "[]" {
		var signinsData []map[string]interface{}
		if err := json.Unmarshal([]byte(result.SigninsJSON), &signinsData); err == nil {
			for _, signinData := range signinsData {
				signin := &model.Signin{}

				// Map signin fields
				if id, ok := signinData["id"].(float64); ok {
					signin.ID = uint64(id)
				}
				if sessionID, ok := signinData["session_id"].(float64); ok {
					signin.SessionID = uint64(sessionID)
				}
				if userID, ok := signinData["user_id"].(float64); ok {
					signin.UserID = &[]uint64{uint64(userID)}[0]
				}
				if expiresAt, ok := signinData["expires_at"].(string); ok {
					signin.ExpiresAt = expiresAt
				}
				if lastActiveAt, ok := signinData["last_active_at"].(string); ok {
					signin.LastActiveAt = lastActiveAt
				}
				if ipAddress, ok := signinData["ip_address"].(string); ok {
					signin.IpAddress = ipAddress
				}
				if browser, ok := signinData["browser"].(string); ok {
					signin.Browser = browser
				}
				if device, ok := signinData["device"].(string); ok {
					signin.Device = device
				}
				if city, ok := signinData["city"].(string); ok {
					signin.City = city
				}
				if region, ok := signinData["region"].(string); ok {
					signin.Region = region
				}
				if country, ok := signinData["country"].(string); ok {
					signin.Country = country
				}

				// Map user data
				if userData, ok := signinData["user"].(map[string]interface{}); ok {
					user := &model.User{}
					if id, ok := userData["id"].(float64); ok {
						user.ID = uint64(id)
					}
					if firstName, ok := userData["first_name"].(string); ok {
						user.FirstName = firstName
					}
					if lastName, ok := userData["last_name"].(string); ok {
						user.LastName = lastName
					}
					if username, ok := userData["username"].(string); ok {
						user.Username = username
					}
					if disabled, ok := userData["disabled"].(bool); ok {
						user.Disabled = disabled
					}
					signin.User = user
				}

				session.Signins = append(session.Signins, *signin)
			}
		}
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
