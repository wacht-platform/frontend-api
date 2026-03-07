package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/wacht-platform/frontend-api/config"
)

type OAuthStateData struct {
	Action       string
	Timestamp    int64
	AttemptID    *uint64
	UserID       *uint64
	SessionID    *uint64
	Provider     string
	RedirectURI  string
	FrontendHost string
}

func GenerateOAuthState(data OAuthStateData, secret []byte) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("secret key is required")
	}

	if data.Timestamp == 0 {
		data.Timestamp = time.Now().Unix()
	}

	var dataStr string
	switch data.Action {
	case "sign_in":
		if data.AttemptID == nil {
			return "", errors.New("attempt_id is required for sign_in action")
		}
		dataStr = fmt.Sprintf("%s|%d|%s|%d|%s",
			data.Action,
			*data.AttemptID,
			data.RedirectURI,
			data.Timestamp,
			data.FrontendHost,
		)
	case "connect_social":
		if data.UserID == nil || data.SessionID == nil {
			return "", errors.New("user_id and session_id are required for connect_social action")
		}
		dataStr = fmt.Sprintf("%s|%d|%d|%s|%s|%d|%s",
			data.Action,
			*data.UserID,
			*data.SessionID,
			data.Provider,
			data.RedirectURI,
			data.Timestamp,
			data.FrontendHost,
		)
	default:
		return "", fmt.Errorf("invalid action: %s", data.Action)
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(dataStr))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	relaySignature, err := generateOAuthRelaySignature([]byte(dataStr))
	if err != nil {
		return "", err
	}

	encodedData := base64.RawURLEncoding.EncodeToString([]byte(dataStr))

	return fmt.Sprintf("%s.%s.%s", encodedData, signature, relaySignature), nil
}

func ValidateOAuthState(state string, secret []byte, maxAge time.Duration) (*OAuthStateData, error) {
	if len(secret) == 0 {
		return nil, errors.New("secret key is required")
	}

	parts := strings.Split(state, ".")
	if len(parts) != 2 && len(parts) != 3 {
		return nil, errors.New("invalid state format")
	}

	dataBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode state data: %w", err)
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(dataBytes)
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return nil, errors.New("invalid state signature")
	}

	dataParts := strings.Split(string(dataBytes), "|")
	if len(dataParts) < 4 {
		return nil, errors.New("invalid state data format")
	}

	result := &OAuthStateData{
		Action: dataParts[0],
	}

	switch result.Action {
	case "sign_in":
		if len(dataParts) != 5 {
			return nil, errors.New("invalid sign_in state format")
		}
		attemptID, err := strconv.ParseUint(dataParts[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid attempt_id: %w", err)
		}
		result.AttemptID = &attemptID
		result.RedirectURI = dataParts[2]
		result.Timestamp, err = strconv.ParseInt(dataParts[3], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid timestamp: %w", err)
		}
		result.FrontendHost = dataParts[4]

	case "connect_social":
		if len(dataParts) != 7 {
			return nil, errors.New("invalid connect_social state format")
		}
		userID, err := strconv.ParseUint(dataParts[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid user_id: %w", err)
		}
		sessionID, err := strconv.ParseUint(dataParts[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid session_id: %w", err)
		}
		result.UserID = &userID
		result.SessionID = &sessionID
		result.Provider = dataParts[3]
		result.RedirectURI = dataParts[4]
		result.Timestamp, err = strconv.ParseInt(dataParts[5], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid timestamp: %w", err)
		}
		result.FrontendHost = dataParts[6]

	default:
		return nil, fmt.Errorf("unknown action: %s", result.Action)
	}

	if maxAge > 0 {
		age := time.Since(time.Unix(result.Timestamp, 0))
		if age > maxAge {
			return nil, fmt.Errorf("state expired (age: %v, max: %v)", age, maxAge)
		}
	}

	return result, nil
}

func GetOAuthStateSecret(deploymentID uint64, privateKey string) []byte {
	data := fmt.Sprintf("oauth_state_%d_%s", deploymentID, privateKey)
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

func getOAuthRelayStateSecret() []byte {
	key := strings.TrimSpace(config.GetEnv("ENCRYPTION_KEY", ""))
	if key == "" {
		return nil
	}
	data := "ors1:" + key
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

func generateOAuthRelaySignature(data []byte) (string, error) {
	secret := getOAuthRelayStateSecret()
	if len(secret) == 0 {
		return "", errors.New("ENCRYPTION_KEY is required for oauth relay state signing")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
