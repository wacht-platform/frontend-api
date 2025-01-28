package middleware

import (
	"errors"
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
	sessionDuration   = 24 * time.Hour
)

func SetSessionMiddleware(c *fiber.Ctx) error {
	deployment := handler.GetDeployment(c)
	sessionToken := getSessionToken(c)

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

	err := database.Connection.Transaction(func(tx *gorm.DB) error {
		var err error
		token, err = utils.SignJWT(
			session.ID,
			deployment.Host,
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
		deployment.Host,
	)

	if errors.Is(err, jwt.TokenExpiredError()) {
		token, err = utils.ParseJWT(
			sessionToken,
			deployment.KepPair,
			deployment.Host,
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

	sessionID, rotatingTokenID, err := extractTokenClaims(expJwt)
	if err != nil {
		return handler.SendUnauthorized(c, err, "Invalid session")
	}

	rotatingToken, err := validateRotatingToken(
		sessionID,
		rotatingTokenID,
	)
	if err != nil {
		return handler.SendUnauthorized(c, err, "Invalid session")
	}

	if err := database.Connection.Delete(&rotatingToken).Error; err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to refresh session",
		)
	}

	var token string

	err = database.Connection.Transaction(func(tx *gorm.DB) error {
		token, err = utils.SignJWT(
			sessionID,
			deployment.Host,
			time.Now().Add(sessionDuration),
			deployment.KepPair,
			tx,
		)

		return err
	})
	if err != nil {
		return handler.SendInternalServerError(
			c,
			err,
			"Failed to refresh session",
		)
	}

	setSessionToken(c, token, deployment.IsProduction())

	c.Locals("session", sessionID)

	return c.Next()
}

func extractTokenClaims(token jwt.Token) (uint, uint, error) {
	var sessionID, rotatingTokenID float64

	if err := token.Get("sess", &sessionID); err != nil {
		return 0, 0, err
	}

	if err := token.Get("rotating_token", &rotatingTokenID); err != nil {
		return 0, 0, err
	}

	return uint(sessionID), uint(rotatingTokenID), nil
}

func validateRotatingToken(
	sessionID uint,
	rotatingTokenID uint,
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
