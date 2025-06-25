package middleware

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/service"
	"github.com/ilabs/wacht-fe/utils"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	sessionCookieName = "__session"
	devSessionHeader  = "X-Development-Session"
	sessionDuration   = 6 * time.Hour
)

type CacheResponse map[string]interface{}

func SetRequestPrelude(c *fiber.Ctx) error {
	host := c.Hostname()
	path := c.Path()

	if net.ParseIP(host) != nil {
		return c.Status(404).JSON(fiber.Map{"message": "Deployment not found"})
	}

	isWellKnown := strings.HasPrefix(path, "/.well")

	if isWellKnown || c.Context().IsOptions() {
		return handleDeploymentOnly(c, host)
	}

	return handleDeploymentAndSession(c, host)
}

func handleDeploymentOnly(c *fiber.Ctx, host string) error {
	deployment, err := getDeploymentFromCacheOrDB(host)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"message": "Deployment not found"})
	}

	c.Locals("deployment", *deployment)
	return c.Next()
}

func handleDeploymentAndSession(c *fiber.Ctx, host string) error {
	sessionToken := getSessionToken(c, host)

	var deployment *model.Deployment
	var session *model.Session
	var err error

	if sessionToken != "" {
		deployment, session, err = getDeploymentAndSessionFromCache(host, sessionToken)
		if err != nil {
			deployment, err = getDeploymentFromCacheOrDB(host)
			if err != nil {
				return c.Status(404).JSON(fiber.Map{"message": "Deployment not found"})
			}
		}
	} else {
		deployment, err = getDeploymentFromCacheOrDB(host)
		if err != nil {
			return c.Status(404).JSON(fiber.Map{"message": "Deployment not found"})
		}
	}

	c.Locals("deployment", *deployment)

	if session != nil {
		c.Locals("session_data", session)
	}

	if sessionToken == "" {
		return handleNewSession(c, *deployment)
	}

	return handleExistingSession(c, *deployment, sessionToken)
}

func getSessionToken(c *fiber.Ctx, host string) string {
	if token := c.Cookies(sessionCookieName); token != "" {
		return token
	}

	deployment, err := getDeploymentFromCacheOrDB(host)
	if err == nil && !deployment.IsProduction() {
		return c.Query("__dev_session__", "")
	}

	return ""
}

func getDeploymentFromCacheOrDB(host string) (*model.Deployment, error) {
	cacheData, err := utils.GetMultipleFromCache(host)
	if err == nil {
		if deploymentData, exists := cacheData[host]; exists {
			deploymentBytes, _ := json.Marshal(deploymentData)
			deployment := new(model.Deployment)
			if json.Unmarshal(deploymentBytes, deployment) == nil {
				return deployment, nil
			}
		}
	}

	return utils.GetDeploymentByHost(host)
}

func getDeploymentAndSessionFromCache(host, sessionToken string) (*model.Deployment, *model.Session, error) {
	sessionID, err := extractSessionIDFromTokenWithoutVerification(sessionToken)
	if err != nil {
		return nil, nil, err
	}

	sessionKey := fmt.Sprintf("session:%d", sessionID)
	keys := fmt.Sprintf("%s,%s", host, sessionKey)

	cacheData, err := utils.GetMultipleFromCache(keys)
	if err != nil {
		return nil, nil, fmt.Errorf("cache miss: %v", err)
	}

	var deployment *model.Deployment
	var session *model.Session

	if deploymentData, exists := cacheData[host]; exists {
		deploymentBytes, _ := json.Marshal(deploymentData)
		deployment = new(model.Deployment)
		json.Unmarshal(deploymentBytes, deployment)
	}

	if sessionData, exists := cacheData[sessionKey]; exists {
		sessionBytes, _ := json.Marshal(sessionData)
		session = new(model.Session)
		json.Unmarshal(sessionBytes, session)
	}

	if deployment == nil || session == nil {
		return nil, nil, fmt.Errorf("incomplete cache data")
	}

	return deployment, session, nil
}

func extractSessionIDFromTokenWithoutVerification(sessionToken string) (uint64, error) {
	parts := strings.Split(sessionToken, ".")
	if len(parts) != 3 {
		return 0, fmt.Errorf("invalid JWT format")
	}

	payload := parts[1]

	padding := 4 - len(payload)%4
	if padding != 4 {
		payload += strings.Repeat("=", padding)
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return 0, fmt.Errorf("failed to decode JWT payload: %v", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return 0, fmt.Errorf("failed to unmarshal JWT claims: %v", err)
	}

	sessionIDClaim, exists := claims["sess"]
	if !exists {
		return 0, fmt.Errorf("sess not found in token")
	}

	sessionID, err := strconv.ParseUint(fmt.Sprintf("%.0f", sessionIDClaim), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid sess format: %v", err)
	}

	return sessionID, nil
}

func handleNewSession(c *fiber.Ctx, deployment model.Deployment) error {
	var token string
	session := model.NewSession()
	deployment.LoadPrivateKey(database.Connection)

	err := database.Connection.Transaction(func(tx *gorm.DB) error {
		var err error
		token, err = utils.SignJWT(
			session.ID,
			deployment.BackendHost,
			time.Now().Add(sessionDuration),
			*deployment.KepPair,
			tx,
		)
		if err != nil {
			return err
		}

		err = tx.Create(session).Error
		return err
	})
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to create a new session",
			handler.ErrInternal,
		)
	}

	setSessionToken(c, token, deployment.IsProduction(), deployment)
	c.Locals("session_data", session)
	c.Locals("session", session.ID)

	go setSessionCache(*session)

	return c.Next()
}

func handleExistingSession(c *fiber.Ctx, deployment model.Deployment, sessionToken string) error {
	token, err := utils.VerifyJWT(sessionToken, *deployment.KepPair, deployment.BackendHost)

	if errors.Is(err, jwt.TokenExpiredError()) {
		token, err = utils.ParseJWT(sessionToken, *deployment.KepPair, deployment.BackendHost)
		if err != nil {
			return handleNewSession(c, deployment)
		}
		return refreshSession(c, token, deployment)
	} else if err != nil {
		return handleNewSession(c, deployment)
	}

	sessionID, _, err := extractTokenClaims(token)
	if err != nil {
		return handleNewSession(c, deployment)
	}

	if cachedSession := c.Locals("session_data"); cachedSession == nil {
		c.Locals("session", sessionID)
	} else {
		session := cachedSession.(*model.Session)
		if session.ID != sessionID {
			c.Locals("session_data", nil)
			c.Locals("session", sessionID)
		} else {
			c.Locals("session", sessionID)
		}
	}

	return c.Next()
}

func setSessionToken(c *fiber.Ctx, token string, isProduction bool, deployment model.Deployment) {
	if isProduction {
		c.Cookie(&fiber.Cookie{
			Name:     sessionCookieName,
			Value:    token,
			Expires:  time.Now().Add(time.Duration(deployment.AuthSettings.SessionInactiveTimeout) * time.Second),
			HTTPOnly: true,
			Secure:   true,
			Domain:   deployment.BackendHost,
		})
	} else {
		c.Set(devSessionHeader, token)
	}
}

func setSessionCache(session model.Session) {
	cacheKey := "session:" + strconv.FormatUint(session.ID, 10)
	utils.SetToCache(cacheKey, session, 3600)
}

func refreshSession(c *fiber.Ctx, expJwt jwt.Token, deployment model.Deployment) error {
	deployment.LoadPrivateKey(database.Connection)

	sessionID, rotatingTokenID, err := extractTokenClaims(expJwt)
	if err != nil {
		log.Println("Error extracting token claims:", err)
		return handler.SendUnauthorized(c, err, "Invalid session")
	}

	var token string
	var finalRotatingTokenID uint64

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		var rotatingToken model.RotatingToken

		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&rotatingToken, rotatingTokenID).Error
		if err != nil {
			return err
		}

		if rotatingToken.SessionID != sessionID {
			return errors.New("invalid rotating token")
		}

		if rotatingToken.HasNextToken() {
			finalRotatingTokenID = 0
			return nil
		}

		newRotatingToken := model.NewRotatingToken(
			sessionID,
			time.Now().Add(sessionDuration).Add(time.Hour*24*30),
		)

		if err := tx.Create(newRotatingToken).Error; err != nil {
			return err
		}

		if err := tx.Model(&rotatingToken).Update("next_token_id", newRotatingToken.ID).Error; err != nil {
			return err
		}

		service.NewCeleryService().ScheduleTokenCleanup(rotatingToken.ID, sessionID, 1)

		finalRotatingTokenID = uint64(newRotatingToken.ID)
		return nil
	})

	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to refresh session")
	}

	if finalRotatingTokenID == 0 {
		// Check if we have cached session data
		if cachedSession := c.Locals("session_data"); cachedSession != nil {
			session := cachedSession.(*model.Session)
			if session.ID == sessionID {
				c.Locals("session", sessionID)
				return c.Next()
			}
		}
		c.Locals("session", sessionID)
		return c.Next()
	}

	signed, err := utils.SignJWT(
		sessionID,
		deployment.BackendHost,
		time.Now().Add(sessionDuration),
		*deployment.KepPair,
		database.Connection,
	)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to build JWT")
	}

	token = string(signed)

	setSessionToken(c, token, deployment.IsProduction(), deployment)

	if cachedSession := c.Locals("session_data"); cachedSession != nil {
		session := cachedSession.(*model.Session)
		if session.ID == sessionID {
			c.Locals("session", sessionID)
			return c.Next()
		}
	}
	c.Locals("session", sessionID)

	return c.Next()
}

func extractTokenClaims(token jwt.Token) (uint64, uint64, error) {
	var sessionIDClaim interface{}

	if err := token.Get("sess", &sessionIDClaim); err != nil || sessionIDClaim == nil {
		return 0, 0, errors.New("sess not found in token")
	}

	var rotatingTokenIDClaim interface{}
	if err := token.Get("rotating_token", &rotatingTokenIDClaim); err != nil || rotatingTokenIDClaim == nil {
		return 0, 0, errors.New("rotating_token not found in token")
	}

	sessionID, err := strconv.ParseUint(fmt.Sprintf("%v", sessionIDClaim), 10, 64)
	if err != nil {
		return 0, 0, errors.New("invalid sess format")
	}

	rotatingTokenID, err := strconv.ParseUint(fmt.Sprintf("%v", rotatingTokenIDClaim), 10, 64)
	if err != nil {
		return 0, 0, errors.New("invalid rotating_token format")
	}

	return sessionID, rotatingTokenID, nil
}
