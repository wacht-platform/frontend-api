package middleware

import (
	"errors"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/utils"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"gorm.io/gorm"
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
		log.Printf("JWT token expired, attempting to refresh session")
		token, err = utils.ParseJWT(
			sessionToken,
			deployment.KepPair,
			deployment.BackendHost,
		)
		if err != nil {
			log.Printf("Failed to parse expired JWT for refresh: %v", err)
			return handler.SendUnauthorized(c, err, "Invalid session")
		}
		return refreshSession(c, token)
	} else if err != nil {
		log.Printf("JWT verification failed: %v", err)
		return handler.SendUnauthorized(c, err, "Invalid session")
	}

	sessionID, _, err := extractTokenClaims(token)
	if err != nil {
		log.Printf("Failed to extract token claims: %v", err)
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
		log.Printf("Failed to extract token claims during refresh: %v", err)
		return handler.SendUnauthorized(c, err, "Invalid session")
	}

	rotatingToken, err := validateRotatingToken(
		sessionID,
		rotatingTokenID,
	)

	if err != nil {
		log.Printf("Failed to validate rotating token during refresh for session %d: %v", sessionID, err)
		log.Printf("Creating new session for session %d due to invalid rotating token", sessionID)
		return handleNewSession(c, deployment)
	}

	var token string

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		newToken, err := utils.SignJWT(
			sessionID,
			deployment.BackendHost,
			time.Now().Add(sessionDuration),
			deployment.KepPair,
			tx,
		)
		if err != nil {
			log.Printf("Failed to sign new JWT during refresh for session %d: %v", sessionID, err)
			return err
		}

		if err := tx.Delete(&rotatingToken).Error; err != nil {
			log.Printf("Failed to delete old rotating token during refresh for session %d: %v", sessionID, err)
			return err
		}

		token = newToken
		return nil
	})

	if err != nil {
		log.Printf("Transaction failed during session refresh for session %d: %v", sessionID, err)
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to refresh session",
		)
	}

	log.Printf("Successfully refreshed session %d", sessionID)
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
		log.Printf("Rotating token %d not found in database: %v", rotatingTokenID, err)
		return rotatingToken, err
	}

	if rotatingToken.SessionID != sessionID {
		log.Printf("Rotating token %d session ID mismatch: expected %d, got %d",
			rotatingTokenID, sessionID, rotatingToken.SessionID)
		return rotatingToken, fiber.NewError(
			fiber.StatusUnauthorized,
			"Invalid rotating token",
		)
	}

	if !rotatingToken.IsValid() {
		log.Printf("Rotating token %d has expired: valid until %v, current time %v",
			rotatingTokenID, rotatingToken.ValidUntil, time.Now())
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
