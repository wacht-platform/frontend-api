package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
	"gorm.io/plugin/dbresolver"
)

func ptr[T any](v T) *T { return &v }

// Helper functions to safely parse IDs from various types
func parseUint64FromInterface(v any) (uint64, error) {
	switch val := v.(type) {
	case string:
		return strconv.ParseUint(val, 10, 64)
	case float64:
		return uint64(val), nil
	case int64:
		return uint64(val), nil
	case nil:
		return 0, fmt.Errorf("value is nil")
	default:
		return 0, fmt.Errorf("unexpected type %T", v)
	}
}

// Helper to safely get string from map
func getStringFromMap(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// Helper to safely get time from map
func getTimeFromMap(m map[string]any, key string) time.Time {
	if v, ok := m[key]; ok {
		// Try to parse as string
		if s, ok := v.(string); ok && s != "" {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				return t
			}
		}
		// Try to parse as time.Time
		if t, ok := v.(time.Time); ok {
			return t
		}
	}
	return time.Time{}
}

// Helper to safely get bool from map
func getBoolFromMap(m map[string]any, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

// Helper to safely get and parse uint64 from map
func getUint64FromMap(m map[string]any, key string) (uint64, error) {
	if v, ok := m[key]; ok {
		return parseUint64FromInterface(v)
	}
	return 0, fmt.Errorf("key %s not found", key)
}

// Helper to safely get and parse optional uint64 from map
func getOptionalUint64FromMap(m map[string]any, key string) *uint64 {
	if v, err := getUint64FromMap(m, key); err == nil {
		return &v
	}
	return nil
}

// Parse user data from map
func parseUserFromMap(userData map[string]any) *model.User {
	if userData == nil {
		return nil
	}

	user := &model.User{}

	// Parse ID
	if id, err := getUint64FromMap(userData, "id"); err == nil {
		user.ID = id
	}

	// Parse string fields
	user.FirstName = getStringFromMap(userData, "first_name")
	user.LastName = getStringFromMap(userData, "last_name")
	user.Username = getStringFromMap(userData, "username")
	user.ProfilePictureURL = getStringFromMap(userData, "profile_picture_url")

	// Parse bool fields
	user.Disabled = getBoolFromMap(userData, "disabled")
	user.HasProfilePicture = getBoolFromMap(userData, "has_profile_picture")

	// Parse availability
	if availability := getStringFromMap(userData, "availability"); availability != "" {
		user.Availability = model.UserAvailability(availability)
	}

	// Parse primary email address ID
	user.PrimaryEmailAddressID = getOptionalUint64FromMap(userData, "primary_email_address_id")

	// Parse primary email address object
	if primaryEmailData, ok := userData["primary_email_address"].(map[string]any); ok {
		user.PrimaryEmailAddress = parsePrimaryEmailFromMap(primaryEmailData)
	}

	return user
}

// Parse primary email from map
func parsePrimaryEmailFromMap(emailData map[string]any) *model.UserEmailAddress {
	if emailData == nil {
		return nil
	}

	email := &model.UserEmailAddress{}

	// Parse ID
	if id, err := getUint64FromMap(emailData, "id"); err == nil {
		email.ID = id
	}

	// Parse string fields
	email.EmailAddress = getStringFromMap(emailData, "email_address")

	// Parse bool fields
	email.IsPrimary = getBoolFromMap(emailData, "is_primary")
	email.Verified = getBoolFromMap(emailData, "verified")

	// Parse verification strategy
	if strategy := getStringFromMap(emailData, "verification_strategy"); strategy != "" {
		email.VerificationStrategy = model.VerificationStrategy(strategy)
	}

	return email
}

// Parse signin from map
func parseSigninFromMap(signinData map[string]any) (*model.Signin, error) {
	if signinData == nil {
		return nil, fmt.Errorf("signin data is nil")
	}

	signin := &model.Signin{}

	// Parse ID (comes as string from SQL)
	if id, err := getUint64FromMap(signinData, "id"); err != nil {
		return nil, fmt.Errorf("failed to parse signin ID: %w", err)
	} else {
		signin.ID = id
	}

	// Parse session ID
	if sessionID, err := getUint64FromMap(signinData, "session_id"); err == nil {
		signin.SessionID = sessionID
	}

	// Parse optional IDs
	signin.UserID = getOptionalUint64FromMap(signinData, "user_id")
	signin.ActiveOrganizationMembershipID = getOptionalUint64FromMap(signinData, "active_organization_membership_id")
	signin.ActiveWorkspaceMembershipID = getOptionalUint64FromMap(signinData, "active_workspace_membership_id")

	// Parse time fields
	signin.ExpiresAt = getTimeFromMap(signinData, "expires_at")
	signin.LastActiveAt = getTimeFromMap(signinData, "last_active_at")
	signin.IpAddress = getStringFromMap(signinData, "ip_address")
	signin.Browser = getStringFromMap(signinData, "browser")
	signin.Device = getStringFromMap(signinData, "device")
	signin.City = getStringFromMap(signinData, "city")
	signin.Region = getStringFromMap(signinData, "region")
	signin.Country = getStringFromMap(signinData, "country")

	// Parse user object if exists
	if userData, ok := signinData["user"].(map[string]any); ok {
		signin.User = parseUserFromMap(userData)
	}

	return signin, nil
}

func GetSessionByID(sessionID uint64) (*model.Session, error) {
	// Check cache first
	if cachedSession, found := GetCachedSession(sessionID); found {
		return cachedSession, nil
	}

	session := new(model.Session)

	mainQuery := `
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

		-- Primary Email Address for Active User
		CASE
			WHEN au.primary_email_address_id IS NOT NULL
			THEN (SELECT json_build_object(
				'id', pe.id,
				'email_address', pe.email_address,
				'is_primary', pe.is_primary,
				'verified', pe.verified,
				'verified_at', pe.verified_at,
				'verification_strategy', pe.verification_strategy,
				'created_at', pe.created_at,
				'updated_at', pe.updated_at
			) FROM user_email_addresses pe WHERE pe.id = au.primary_email_address_id)
			ELSE NULL
		END as "ActiveSignin__User__primary_email_address",

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
					'required_fields', sia.required_fields,
					'first_method_authenticated', sia.first_method_authenticated,
					'second_method_authenticated', sia.second_method_authenticated,
					'second_method_authentication_required', sia.second_method_authentication_required,
					'available_2fa_methods', sia.available_2fa_methods
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
					'id', si.id::text,
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
						'id', u.id::text,
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
						'backup_codes_generated', u.backup_codes_generated,
						'primary_email_address', CASE
							WHEN u.primary_email_address_id IS NOT NULL
							THEN (SELECT json_build_object(
								'id', pe.id::text,
								'email_address', pe.email_address,
								'is_primary', pe.is_primary,
								'verified', pe.verified,
								'verified_at', pe.verified_at,
								'verification_strategy', pe.verification_strategy
							) FROM user_email_addresses pe WHERE pe.id = u.primary_email_address_id)
							ELSE NULL
						END
					)
				) ORDER BY si.created_at DESC
			) FROM signins si
			LEFT JOIN users u ON si.user_id = u.id
			WHERE si.session_id = s.id AND (si.expires_at > NOW() OR si.expires_at IS NULL OR si.expires_at = '')),
			'[]'::json
		) as signins

	FROM sessions s
	LEFT JOIN signins asi ON s.active_signin_id = asi.id AND (asi.expires_at > NOW() OR asi.expires_at IS NULL OR asi.expires_at = '')
	LEFT JOIN users au ON asi.user_id = au.id
	LEFT JOIN organization_memberships aom ON asi.active_organization_membership_id = aom.id
	LEFT JOIN workspace_memberships awm ON asi.active_workspace_membership_id = awm.id
	WHERE s.id = ? AND s.deleted_at IS NULL`

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

	var rawResult map[string]any
	err := database.Connection.Clauses(dbresolver.Read).Raw(mainQuery, sessionID).Scan(&rawResult).Error
	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	// Parse session ID
	if id, err := parseUint64FromInterface(rawResult["id"]); err == nil {
		session.ID = id
	} else {
		log.Printf("Warning: failed to parse session ID: %v", err)
	}

	// Parse active signin ID
	if activeSigninID, err := parseUint64FromInterface(rawResult["active_signin_id"]); err == nil {
		session.ActiveSigninID = ptr(activeSigninID)
	}

	// Parse active signin if exists
	if activeSigninID, err := parseUint64FromInterface(rawResult["ActiveSignin__id"]); err == nil {
		session.ActiveSignin = &model.Signin{}
		session.ActiveSignin.ID = activeSigninID

		// Parse signin fields
		if sessionID, err := parseUint64FromInterface(rawResult["ActiveSignin__session_id"]); err == nil {
			session.ActiveSignin.SessionID = sessionID
		}

		session.ActiveSignin.UserID = getOptionalUint64FromMap(rawResult, "ActiveSignin__user_id")
		session.ActiveSignin.ActiveOrganizationMembershipID = getOptionalUint64FromMap(rawResult, "ActiveSignin__active_organization_membership_id")
		session.ActiveSignin.ActiveWorkspaceMembershipID = getOptionalUint64FromMap(rawResult, "ActiveSignin__active_workspace_membership_id")

		// Parse string fields
		session.ActiveSignin.ExpiresAt = getTimeFromMap(rawResult, "ActiveSignin__expires_at")
		session.ActiveSignin.LastActiveAt = getTimeFromMap(rawResult, "ActiveSignin__last_active_at")
		session.ActiveSignin.IpAddress = getStringFromMap(rawResult, "ActiveSignin__ip_address")
		session.ActiveSignin.Browser = getStringFromMap(rawResult, "ActiveSignin__browser")
		session.ActiveSignin.Device = getStringFromMap(rawResult, "ActiveSignin__device")
		session.ActiveSignin.City = getStringFromMap(rawResult, "ActiveSignin__city")
		session.ActiveSignin.Region = getStringFromMap(rawResult, "ActiveSignin__region")
		session.ActiveSignin.RegionCode = getStringFromMap(rawResult, "ActiveSignin__region_code")
		session.ActiveSignin.Country = getStringFromMap(rawResult, "ActiveSignin__country")
		session.ActiveSignin.CountryCode = getStringFromMap(rawResult, "ActiveSignin__country_code")

		// Parse user if exists
		if userID, err := parseUint64FromInterface(rawResult["ActiveSignin__User__id"]); err == nil {
			session.ActiveSignin.User = &model.User{
				FirstName:         getStringFromMap(rawResult, "ActiveSignin__User__first_name"),
				LastName:          getStringFromMap(rawResult, "ActiveSignin__User__last_name"),
				Username:          getStringFromMap(rawResult, "ActiveSignin__User__username"),
				Disabled:          getBoolFromMap(rawResult, "ActiveSignin__User__disabled"),
				HasProfilePicture: getBoolFromMap(rawResult, "ActiveSignin__User__has_profile_picture"),
				ProfilePictureURL: getStringFromMap(rawResult, "ActiveSignin__User__profile_picture_url"),
			}
			session.ActiveSignin.User.ID = userID

			// Parse availability
			if availability := getStringFromMap(rawResult, "ActiveSignin__User__availability"); availability != "" {
				session.ActiveSignin.User.Availability = model.UserAvailability(availability)
			}

			// Parse primary email address ID
			session.ActiveSignin.User.PrimaryEmailAddressID = getOptionalUint64FromMap(rawResult, "ActiveSignin__User__primary_email_address_id")

			// Parse primary email JSON
			if primaryEmailJSON := getStringFromMap(rawResult, "ActiveSignin__User__primary_email_address"); primaryEmailJSON != "" {
				var primaryEmailMap map[string]any
				if err := json.Unmarshal([]byte(primaryEmailJSON), &primaryEmailMap); err == nil {
					session.ActiveSignin.User.PrimaryEmailAddress = parsePrimaryEmailFromMap(primaryEmailMap)
				} else {
					log.Printf("Warning: failed to parse primary email JSON: %v", err)
				}
			}
		}

		// Parse active organization membership
		if orgMembershipID, err := parseUint64FromInterface(rawResult["ActiveSignin__ActiveOrganizationMembership__id"]); err == nil {
			session.ActiveSignin.ActiveOrganizationMembership = &model.OrganizationMembership{}
			session.ActiveSignin.ActiveOrganizationMembership.ID = orgMembershipID

			if orgID, err := parseUint64FromInterface(rawResult["ActiveSignin__ActiveOrganizationMembership__organization_id"]); err == nil {
				session.ActiveSignin.ActiveOrganizationMembership.OrganizationID = orgID
			}
			if userID, err := parseUint64FromInterface(rawResult["ActiveSignin__ActiveOrganizationMembership__user_id"]); err == nil {
				session.ActiveSignin.ActiveOrganizationMembership.UserID = userID
			}
		}

		// Parse active workspace membership
		if wsMembershipID, err := parseUint64FromInterface(rawResult["ActiveSignin__ActiveWorkspaceMembership__id"]); err == nil {
			session.ActiveSignin.ActiveWorkspaceMembership = &model.WorkspaceMembership{}
			session.ActiveSignin.ActiveWorkspaceMembership.ID = wsMembershipID

			if wsID, err := parseUint64FromInterface(rawResult["ActiveSignin__ActiveWorkspaceMembership__workspace_id"]); err == nil {
				session.ActiveSignin.ActiveWorkspaceMembership.WorkspaceID = wsID
			}
			if userID, err := parseUint64FromInterface(rawResult["ActiveSignin__ActiveWorkspaceMembership__user_id"]); err == nil {
				session.ActiveSignin.ActiveWorkspaceMembership.UserID = userID
			}
			if orgMembershipID, err := parseUint64FromInterface(rawResult["ActiveSignin__ActiveWorkspaceMembership__organization_membership_id"]); err == nil {
				session.ActiveSignin.ActiveWorkspaceMembership.OrganizationMembershipID = orgMembershipID
			}
		}
	}

	if signinsJSON := getStringFromMap(rawResult, "signins"); signinsJSON != "" && signinsJSON != "[]" {
		var signinsArray []map[string]any
		if err := json.Unmarshal([]byte(signinsJSON), &signinsArray); err != nil {
			log.Printf("Error: failed to unmarshal signins JSON: %v", err)
		} else {
			session.Signins = make([]model.Signin, 0, len(signinsArray))
			for _, signinMap := range signinsArray {
				if signin, err := parseSigninFromMap(signinMap); err != nil {
					log.Printf("Warning: failed to parse signin: %v", err)
				} else {
					session.Signins = append(session.Signins, *signin)
				}
			}
		}
	}

	// Cache the session before returning
	SetCachedSession(sessionID, session)

	return session, nil
}
