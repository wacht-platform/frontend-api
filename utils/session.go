package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
)

type SessionQueryResult struct {
	model.Session
	SigninAttempts []byte `gorm:"column:signin_attempts"`
	Signins        []byte `gorm:"column:signins"`
	SignupAttempts []byte `gorm:"column:signup_attempts"`
	ActiveSignin   []byte `gorm:"column:active_signin"`
}

func GetSessionByID(sessionID uint64) (*model.Session, error) {
	cacheKey := "session:" + strconv.FormatUint(sessionID, 10)
	resp, err := http.Get(os.Getenv("CACHE_WORKER") + "?q=" + cacheKey)
	if err == nil && resp.StatusCode == 200 {
		session := new(model.Session)
		if err := GetFromCache(resp, session); err == nil {
			return session, nil
		}
	}

	queryResult := new(SessionQueryResult)
	rawSQL := `
		WITH user_email_addresses_agg AS (
			SELECT user_id, json_agg(uea) AS user_email_addresses
			FROM user_email_addresses uea
			GROUP BY user_id
		),
		user_phone_numbers_agg AS (
			SELECT user_id, json_agg(upn) AS user_phone_numbers
			FROM user_phone_numbers upn
			GROUP BY user_id
		),
		social_connections_agg AS (
			SELECT user_id, json_agg(sc) AS social_connections
			FROM social_connections sc
			GROUP BY user_id
		),
		users_agg AS (
			SELECT
				u.id,
				json_build_object(
					'id', u.id,
					'created_at', u.created_at,
					'updated_at', u.updated_at,
					'first_name', u.first_name,
					'has_profile_picture', u.has_profile_picture,
					'profile_picture_url', u.profile_picture_url,
					'last_name', u.last_name,
					'username', u.username,
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
					'user_email_addresses', uea.user_email_addresses,
					'user_phone_numbers', upn.user_phone_numbers,
					'social_connections', sc.social_connections
				) as user
			FROM users u
			LEFT JOIN user_email_addresses_agg uea ON u.id = uea.user_id
			LEFT JOIN user_phone_numbers_agg upn ON u.id = upn.user_id
			LEFT JOIN social_connections_agg sc ON u.id = sc.user_id
		),
		signins_agg AS (
			SELECT
				s.id as session_id,
				json_agg(json_build_object(
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
					'user', ua.user
				)) as signins
			FROM sessions s
			JOIN signins si ON s.id = si.session_id
			JOIN users_agg ua ON si.user_id = ua.id
			GROUP BY s.id
		),
		active_signin_agg AS (
			SELECT
				s.id as session_id,
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
					'user', ua.user
				) as active_signin
			FROM sessions s
			JOIN signins si ON s.active_signin_id = si.id
			JOIN users_agg ua ON si.user_id = ua.id
		),
		signin_attempts_agg AS (
			SELECT session_id, json_agg(sa) as signin_attempts
			FROM sign_in_attempts sa
			GROUP BY session_id
		),
		signup_attempts_agg AS (
			SELECT session_id, json_agg(sua) as signup_attempts
			FROM signup_attempts sua
			GROUP BY session_id
		)
		SELECT
			s.*,
			sa.signin_attempts,
			si.signins,
			sua.signup_attempts,
			asi.active_signin
		FROM sessions s
		LEFT JOIN signin_attempts_agg sa ON s.id = sa.session_id
		LEFT JOIN signins_agg si ON s.id = si.session_id
		LEFT JOIN signup_attempts_agg sua ON s.id = sua.session_id
		LEFT JOIN active_signin_agg asi ON s.id = asi.session_id
		WHERE s.id = ? AND s.deleted_at IS NULL
	`
	err = database.Connection.Raw(rawSQL, sessionID).Scan(queryResult).Error

	if err != nil || queryResult.ID == 0 {
		return nil, fmt.Errorf("session not found")
	}

	session := &queryResult.Session
	json.Unmarshal(queryResult.SigninAttempts, &session.SigninAttempts)
	json.Unmarshal(queryResult.Signins, &session.Signins)
	json.Unmarshal(queryResult.SignupAttempts, &session.SignupAttempts)
	json.Unmarshal(queryResult.ActiveSignin, &session.ActiveSignin)

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
