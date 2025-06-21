package middleware

import (
	"errors"
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

func SetSessionMiddleware(c *fiber.Ctx) error {
	deployment := handler.GetDeployment(c)
	sessionToken := getSessionToken(c)

	path := c.Path()

	if strings.HasPrefix(path, "/.well") {
		return c.Next()
	}

	if sessionToken == "" {
		return handleNewSession(c, deployment)
	}

	return handleExistingSession(c, deployment, sessionToken)
}

func getSessionToken(c *fiber.Ctx) string {
	deployment := handler.GetDeployment(c)

	if token := c.Cookies(sessionCookieName); token != "" {
		return token
	}

	if !deployment.IsProduction() {
		return c.Get(devSessionHeader)
	}

	return ""
}

func handleNewSession(
	c *fiber.Ctx,
	deployment model.Deployment,
) error {
	var token string
	session := model.NewSession()
	deployment.LoadPrivateKey(database.Connection)

	err := database.Connection.Transaction(func(tx *gorm.DB) error {
		var err error
		token, err = utils.SignJWT(
			session.ID,
			deployment.BackendHost,
			time.Now().Add(sessionDuration),
			deployment.KepPair,
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

	setSessionToken(c, token, deployment.IsProduction())

	c.Locals("session", session.ID)

	return c.Next()
}

func handleExistingSession(
	c *fiber.Ctx,
	deployment model.Deployment,
	sessionToken string,
) error {
	token, err := utils.VerifyJWT(
		sessionToken,
		deployment.KepPair,
		deployment.BackendHost,
	)

	if errors.Is(err, jwt.TokenExpiredError()) {
		token, err = utils.ParseJWT(
			sessionToken,
			deployment.KepPair,
			deployment.BackendHost,
		)
		if err != nil {
			return handleNewSession(c, deployment)
		}
		return refreshSession(c, token)
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

func setSessionToken(c *fiber.Ctx, token string, isProduction bool) {
	deployment := handler.GetDeployment(c)

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

func refreshSession(c *fiber.Ctx, expJwt jwt.Token) error {
	deployment := handler.GetDeployment(c)
	deployment.LoadPrivateKey(database.Connection)

	sessionID, rotatingTokenID, err := extractTokenClaims(expJwt)
	if err != nil {
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
			return fiber.NewError(fiber.StatusUnauthorized, "Invalid rotating token")
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
		c.Locals("session", sessionID)
		return c.Next()
	}

	signed, err := utils.SignJWT(
		sessionID,
		deployment.BackendHost,
		time.Now().Add(sessionDuration),
		deployment.KepPair,
		database.Connection,
	)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to build JWT")
	}

	token = string(signed)

	setSessionToken(c, token, deployment.IsProduction())
	c.Locals("session", sessionID)

	return c.Next()
}

func extractTokenClaims(token jwt.Token) (uint64, uint64, error) {
	var sessionID float64
	var rotatingTokenID string

	if err := token.Get("sess", &sessionID); err != nil {
		return 0, 0, err
	}

	if err := token.Get("rotating_token", &rotatingTokenID); err != nil {
		return 0, 0, err
	}

	rotatingTokenIDuint64, err := strconv.ParseUint(rotatingTokenID, 10, 64)
	if err != nil {
		return 0, 0, err
	}

	return uint64(sessionID), uint64(rotatingTokenIDuint64), nil
}
