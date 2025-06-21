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
					'first_name', u.first_name,
					'last_name', u.last_name,
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
					'user_id', si.user_id,
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
					'user_id', si.user_id,
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
	err := SetToCache(cacheKey, session, 3600) // Cache for 1 hour
	if err != nil {
		log.Println("Error setting session cache: ", err)
	}
}
