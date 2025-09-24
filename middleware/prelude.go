package middleware

import (
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
	var err error

	deployment, err = getDeploymentFromCacheOrDB(host)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"message": "Deployment not found"})
	}

	c.Locals("deployment", *deployment)

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
	return utils.GetDeploymentByHost(host)
}

func handleNewSession(c *fiber.Ctx, deployment model.Deployment) error {
	var token string
	session := model.NewSession()
	deployment.LoadPrivateKey(database.Connection)

	err := database.Connection.Transaction(func(tx *gorm.DB) error {
		var err error
		token, err = utils.SignNewJWT(
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

	c.Locals("session", sessionID)

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
			finalRotatingTokenID = *rotatingToken.NextTokenID
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

		// Schedule token cleanup via NATS
		natsService, err := service.NewNatsService()
		if err == nil {
			natsService.ScheduleTokenCleanup(uint64(rotatingToken.ID), sessionID, 1)
		}

		finalRotatingTokenID = uint64(newRotatingToken.ID)
		return nil
	})

	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to refresh session")
	}

	if finalRotatingTokenID == 0 {
		c.Locals("session", sessionID)
		return c.Next()
	}

	signed, err := utils.SignJWT(
		sessionID,
		finalRotatingTokenID,
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

	var sessionID uint64
	switch v := sessionIDClaim.(type) {
	case float64:
		sessionID = uint64(v)
	case int64:
		sessionID = uint64(v)
	case int:
		sessionID = uint64(v)
	case string:
		var err error
		sessionID, err = strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0, 0, errors.New("invalid sess format")
		}
	default:
		var err error
		sessionID, err = strconv.ParseUint(fmt.Sprintf("%v", sessionIDClaim), 10, 64)
		if err != nil {
			return 0, 0, errors.New("invalid sess format")
		}
	}

	var rotatingTokenID uint64
	switch v := rotatingTokenIDClaim.(type) {
	case float64:
		rotatingTokenID = uint64(v)
	case int64:
		rotatingTokenID = uint64(v)
	case int:
		rotatingTokenID = uint64(v)
	case string:
		var err error
		rotatingTokenID, err = strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0, 0, errors.New("invalid rotating_token format")
		}
	default:
		var err error
		rotatingTokenID, err = strconv.ParseUint(fmt.Sprintf("%v", rotatingTokenIDClaim), 10, 64)
		if err != nil {
			return 0, 0, errors.New("invalid rotating_token format")
		}
	}

	return sessionID, rotatingTokenID, nil
}
