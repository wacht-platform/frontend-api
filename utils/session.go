package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
)

func GetSessionByID(sessionID uint64) (*model.Session, error) {
	if cachedSession, found := GetCachedSession(sessionID); found {
		return cachedSession, nil
	}

	var rawJSON string
	err := database.Connection.Raw(sessionQuery, sessionID).Scan(&rawJSON).Error
	if err != nil {
		log.Printf("failed to fetch session: %v", err)
		return nil, fmt.Errorf("failed to fetch session: %w", err)
	}

	session := new(model.Session)
	if err := json.Unmarshal([]byte(rawJSON), session); err != nil {
		log.Printf("failed to parse session data: %v", err)
		return nil, fmt.Errorf("failed to parse session data: %w", err)
	}

	populatePrimaryFields := func(u *model.User) {
		if u == nil {
			return
		}
		if u.PrimaryEmailAddressID != nil {
			for i := range u.UserEmailAddresses {
				if u.UserEmailAddresses[i].ID == *u.PrimaryEmailAddressID {
					u.PrimaryEmailAddress = &u.UserEmailAddresses[i]
					break
				}
			}
		}

		if u.PrimaryEmailAddress == nil {
			for i := range u.UserEmailAddresses {
				if u.UserEmailAddresses[i].IsPrimary {
					u.PrimaryEmailAddress = &u.UserEmailAddresses[i]
					break
				}
			}
		}

		if u.PrimaryPhoneNumberID != nil {
			for i := range u.UserPhoneNumbers {
				if u.UserPhoneNumbers[i].ID == *u.PrimaryPhoneNumberID {
					u.PrimaryPhoneNumber = &u.UserPhoneNumbers[i]
					break
				}
			}
		}
	}

	for i := range session.Signins {
		if session.Signins[i].User != nil {
			populatePrimaryFields(session.Signins[i].User)
		}
	}

	if session.ActiveSigninID != nil {
		for i := range session.Signins {
			if session.Signins[i].ID == *session.ActiveSigninID {
				session.ActiveSignin = &session.Signins[i]
				break
			}
		}
	}

	SetCachedSession(sessionID, session)
	return session, nil
}

func UpdateSessionLastActive(sessionID uint64) {
	ctx := context.Background()
	key := fmt.Sprintf("session:last_active:%d", sessionID)

	if database.Redis.Get(ctx, key).Err() == nil {
		return
	}

	database.Redis.Set(ctx, key, "1", 5*time.Minute)

	database.Connection.Exec(`
		UPDATE signins
		SET last_active_at = NOW()
		WHERE id = (
			SELECT active_signin_id
			FROM sessions
			WHERE id = ?
		)`, sessionID)
}

// --- SQL Queries ---

const (
	fmtTime = "'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'"

	userJSONSelect = `
	json_build_object(
		'id', u.id::text,
		'created_at', to_char(u.created_at, ` + fmtTime + `),
		'updated_at', to_char(u.updated_at, ` + fmtTime + `),
		'first_name', u.first_name,
		'last_name', u.last_name,
		'username', u.username,
		'has_profile_picture', u.has_profile_picture,
		'profile_picture_url', u.profile_picture_url,
		'availability', u.availability,
		'last_password_reset_at', to_char(u.last_password_reset_at, ` + fmtTime + `),
		'schema_version', u.schema_version,
		'disabled', u.disabled,
		'primary_email_address_id', u.primary_email_address_id::text,
		'primary_phone_number_id', u.primary_phone_number_id::text,
		'second_factor_policy', u.second_factor_policy,
		'active_organization_membership_id', u.active_organization_membership_id::text,
		'active_workspace_membership_id', u.active_workspace_membership_id::text,
		'public_metadata', u.public_metadata,
		'backup_codes_generated', u.backup_codes_generated,
		'has_passkeys', EXISTS(SELECT 1 FROM user_passkeys upk WHERE upk.user_id = u.id),
		'has_password', CASE WHEN u.password != '' AND u.password IS NOT NULL THEN true ELSE false END,
		'user_email_addresses', COALESCE((
			SELECT json_agg(json_build_object(
				'id', ue.id::text, 'email', ue.email_address, 'is_primary', ue.is_primary, 
				'verified', ue.verified, 
				'verified_at', to_char(ue.verified_at, ` + fmtTime + `), 
				'verification_strategy', ue.verification_strategy,
				'created_at', to_char(ue.created_at, ` + fmtTime + `), 
				'updated_at', to_char(ue.updated_at, ` + fmtTime + `)
			) ORDER BY ue.is_primary DESC, ue.created_at) 
			FROM user_email_addresses ue WHERE ue.user_id = u.id
		), '[]'),
		'user_phone_numbers', COALESCE((
			SELECT json_agg(json_build_object(
				'id', up.id::text, 'phone_number', up.phone_number, 'country_code', up.country_code, 
				'verified', up.verified, 
				'verified_at', to_char(up.verified_at, ` + fmtTime + `),
				'created_at', to_char(up.created_at, ` + fmtTime + `), 
				'updated_at', to_char(up.updated_at, ` + fmtTime + `)
			) ORDER BY up.created_at) 
			FROM user_phone_numbers up WHERE up.user_id = u.id
		), '[]'),
		'social_connections', COALESCE((
			SELECT json_agg(json_build_object(
				'id', sc.id::text, 'provider', sc.provider, 'user_email_address_id', sc.user_email_address_id::text, 
				'email_address', sc.email_address, 'first_name', sc.first_name, 'last_name', sc.last_name,
				'created_at', to_char(sc.created_at, ` + fmtTime + `), 
				'updated_at', to_char(sc.updated_at, ` + fmtTime + `)
			) ORDER BY sc.created_at) 
			FROM social_connections sc WHERE sc.user_id = u.id
		), '[]'),
		'segments', COALESCE((
			SELECT json_agg(json_build_object(
				'id', us_seg.id::text, 
				'created_at', to_char(us_seg.created_at, ` + fmtTime + `), 
				'updated_at', to_char(us_seg.updated_at, ` + fmtTime + `), 
				'deployment_id', us_seg.deployment_id::text, 'name', us_seg.name, 'type', us_seg.type
			)) 
			FROM user_segments us JOIN segments us_seg ON us.segment_id = us_seg.id 
			WHERE us.user_id = u.id AND us_seg.deleted_at IS NULL
		), '[]'),
		'user_authenticator', (
			SELECT json_build_object(
				'id', ua.id::text, 
				'created_at', to_char(ua.created_at, ` + fmtTime + `), 
				'updated_at', to_char(ua.updated_at, ` + fmtTime + `), 
				'user_id', ua.user_id::text, 'otp_url', ua.otp_url
			) 
			FROM user_authenticators ua WHERE ua.user_id = u.id AND ua.deleted_at IS NULL LIMIT 1
		)
	)`

	signinAttemptsSelect = `
	COALESCE((
		SELECT json_agg(json_build_object(
			'id', sia.id::text, 
			'created_at', to_char(sia.created_at, ` + fmtTime + `), 
			'updated_at', to_char(sia.updated_at, ` + fmtTime + `), 
			'expires_at', to_char(sia.expires_at, ` + fmtTime + `),
			'user_id', sia.user_id::text, 
			'identifier_id', sia.identifier_id::text, 
			'session_id', sia.session_id::text, 
			'method', sia.method, 
			'sso_provider', sia.sso_provider, 
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
		) ORDER BY sia.created_at ASC) 
		FROM sign_in_attempts sia WHERE sia.session_id = s.id
	), '[]')`

	signupAttemptsSelect = `
	COALESCE((
		SELECT json_agg(json_build_object(
			'id', sua.id::text, 
			'created_at', to_char(sua.created_at, ` + fmtTime + `), 
			'updated_at', to_char(sua.updated_at, ` + fmtTime + `), 
			'session_id', sua.session_id::text, 
			'first_name', sua.first_name, 
			'last_name', sua.last_name, 
			'email', sua.email, 
			'username', sua.username, 
			'phone_number', sua.phone_number, 
			'phone_country_code', sua.phone_country_code, 
			'required_fields', sua.required_fields, 
			'missing_fields', sua.missing_fields, 
			'current_step', sua.current_step, 
			'remaining_steps', sua.remaining_steps, 
			'sso_provider', sua.sso_provider, 
			'is_oauth_signup', sua.is_oauth_signup, 
			'completed', sua.completed
		) ORDER BY sua.created_at ASC) 
		FROM signup_attempts sua WHERE sua.session_id = s.id
	), '[]')`

	signinsSelect = `
	COALESCE((
		SELECT json_agg(json_build_object(
			'id', si.id::text, 
			'created_at', to_char(si.created_at, ` + fmtTime + `), 
			'updated_at', to_char(si.updated_at, ` + fmtTime + `), 
			'expires_at', to_char(si.expires_at, ` + fmtTime + `), 
			'last_active_at', to_char(si.last_active_at, ` + fmtTime + `), 
			'session_id', si.session_id::text, 
			'user_id', si.user_id::text, 
			'active_organization_membership_id', si.active_organization_membership_id::text, 
			'active_workspace_membership_id', si.active_workspace_membership_id::text, 
			'ip_address', si.ip_address, 
			'browser', si.browser, 
			'device', si.device, 
			'city', si.city, 
			'region', si.region, 
			'country', si.country,
			'user', ` + userJSONSelect + `,
			'active_organization_membership', (
				SELECT json_build_object(
					'id', aom.id::text,
					'organization_id', aom.organization_id::text,
					'user_id', aom.user_id::text,
					'public_metadata', aom.public_metadata,
					'organization', json_build_object(
						'id', ao.id::text,
						'name', ao.name,
						'image_url', ao.image_url,
						'description', ao.description, 
						'member_count', ao.member_count,
						'enforce_mfa', ao.enforce_mfa_setup,
						'enable_ip_restriction', ao.enable_ip_restriction,
						'public_metadata', ao.public_metadata
					),
					'roles', (
						SELECT json_agg(json_build_object(
							'id', r.id::text,
							'name', r.name,
							'deployment_id', r.deployment_id::text,
							'created_at', to_char(r.created_at, ` + fmtTime + `),
							'updated_at', to_char(r.updated_at, ` + fmtTime + `),
							'permissions', r.permissions
						))
						FROM organization_membership_roles omr 
						JOIN organization_roles r ON omr.organization_role_id = r.id 
						WHERE omr.organization_membership_id = aom.id
					)
				)
				FROM organization_memberships aom 
				JOIN organizations ao ON aom.organization_id = ao.id
				WHERE aom.id = si.active_organization_membership_id
			),
			'active_workspace_membership', (
				SELECT json_build_object(
					'id', awm.id::text,
					'workspace_id', awm.workspace_id::text,
					'user_id', awm.user_id::text,
					'organization_id', awm.organization_id::text,
					'organization_membership_id', awm.organization_membership_id::text,
					'public_metadata', awm.public_metadata,
					'workspace', json_build_object(
						'id', aw.id::text,
						'name', aw.name,
						'image_url', aw.image_url,
						'description', aw.description,
						'member_count', aw.member_count,
						'enforce_mfa', aw.enforce_mfa_setup,
						'enable_ip_restriction', aw.enable_ip_restriction,
						'public_metadata', aw.public_metadata
					),
					'roles', (
						SELECT json_agg(json_build_object(
							'id', r.id::text,
							'name', r.name,
							'permissions', r.permissions
						))
						FROM workspace_membership_roles wmr
						JOIN workspace_roles r ON wmr.workspace_role_id = r.id
						WHERE wmr.workspace_membership_id = awm.id
					)
				)
				FROM workspace_memberships awm
				JOIN workspaces aw ON awm.workspace_id = aw.id
				WHERE awm.id = si.active_workspace_membership_id
			)
		) ORDER BY si.created_at DESC) 
		FROM signins si 
		LEFT JOIN users u ON si.user_id = u.id 
		WHERE si.session_id = s.id AND (si.expires_at > NOW() OR si.expires_at IS NULL)
	), '[]')`

	sessionQuery = `
	SELECT json_build_object(
		'id', s.id::text,
		'created_at', to_char(s.created_at, ` + fmtTime + `),
		'updated_at', to_char(s.updated_at, ` + fmtTime + `),
		'active_signin_id', s.active_signin_id::text,
		'signin_attempts', ` + signinAttemptsSelect + `,
		'signup_attempts', ` + signupAttemptsSelect + `,
		'signins', ` + signinsSelect + `
	)
	FROM sessions s
	WHERE s.id = ? AND s.deleted_at IS NULL
	`
)
