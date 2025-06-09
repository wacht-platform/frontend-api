package middleware

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/utils"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	sessionCookieName = "__session"
	devSessionHeader  = "X-Development-Session"
	sessionDuration   = 1 * time.Minute
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
	if token := c.Cookies(sessionCookieName); token != "" {
		return token
	}
	return c.Get(devSessionHeader)
}

func handleNewSession(
	c *fiber.Ctx,
	deployment model.Deployment,
) error {
	var token string
	session := model.NewSession()
	deployment.LoadKepPair(database.Connection)

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
	deployment.LoadKepPair(database.Connection)

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
			return handler.SendUnauthorized(c, err, "Invalid session")
		}
		return refreshSession(c, token)
	} else if err != nil {
		return handler.SendUnauthorized(c, err, "Invalid session")
	}

	sessionID, _, err := extractTokenClaims(token)
	if err != nil {
		return handler.SendUnauthorized(c, err, "Invalid session")
	}

	c.Locals("session", sessionID)

	return c.Next()
}

func setSessionToken(c *fiber.Ctx, token string, isProduction bool) {
	if isProduction {
		c.Cookie(&fiber.Cookie{
			Name:     sessionCookieName,
			Value:    token,
			Expires:  time.Now().Add(sessionDuration),
			HTTPOnly: true,
		})
	} else {
		c.Set(devSessionHeader, token)
	}
}

func refreshSession(c *fiber.Ctx, expJwt jwt.Token) error {
	deployment := handler.GetDeployment(c)
	deployment.LoadKepPair(database.Connection)

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

	tok, err := jwt.NewBuilder().
		Issuer(fmt.Sprintf("https://%s", deployment.BackendHost)).
		Expiration(time.Now().Add(sessionDuration)).
		IssuedAt(time.Now()).
		NotBefore(time.Now()).
		Claim("sess", sessionID).
		Claim("rotating_token", strconv.FormatUint(finalRotatingTokenID, 10)).
		Build()
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to build JWT")
	}

	privateKeyBlock, _ := pem.Decode([]byte(deployment.KepPair.PrivateKey))
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to parse private key")
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), privateKey))
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to sign JWT")
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

func validateRotatingToken(
	sessionID uint64,
	rotatingTokenID uint64,
) (model.RotatingToken, error) {
	var rotatingToken model.RotatingToken
	if err := database.Connection.First(&rotatingToken, rotatingTokenID).Error; err != nil {
		return rotatingToken, err
	}

	if rotatingToken.SessionID != sessionID ||
		!rotatingToken.IsValid() {
		return rotatingToken, fiber.NewError(
			fiber.StatusUnauthorized,
			"Invalid rotating token",
		)
	}

	return rotatingToken, nil
}

// Fixed Window Rate Limiting for the API endpoints to prevent abuse of the service by a single user or IP address (7 requests per 10 seconds).
func RateLimiter() fiber.Handler {
	// storage :=  redis.New(redis.Config{

	// })

	return limiter.New(limiter.Config{
		Max:        7,
		Expiration: 10 * time.Second,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return fiber.NewError(
				fiber.StatusTooManyRequests,
				"Too many requests, please try again later.",
			)
		},
		//  Storage: storage,
	})
}
