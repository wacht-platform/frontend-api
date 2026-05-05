package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/limiter"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/service"
)

const (
	sessionTokenPairLimit    = 10
	sessionTokenServerLimit  = 2000
	sessionTokenSessionLimit = 30
	sessionTokenWindow       = time.Minute
	wachtForwardedForHeader  = "X-Wacht-Forwarded-For"
)

func SessionTokenRateLimiters(natsService *service.NatsService) []fiber.Handler {
	storage := NewNatsStorage(natsService)

	return []fiber.Handler{
		newSessionTokenRateLimiter(storage, sessionTokenPairLimit, sessionTokenPairRateLimitKey),
		newSessionTokenRateLimiter(storage, sessionTokenServerLimit, sessionTokenServerRateLimitKey),
		newSessionTokenRateLimiter(storage, sessionTokenSessionLimit, sessionTokenSessionRateLimitKey),
	}
}

func newSessionTokenRateLimiter(
	storage fiber.Storage,
	max int,
	keyGenerator func(fiber.Ctx) string,
) fiber.Handler {
	return limiter.New(limiter.Config{
		Max:        max,
		Expiration: sessionTokenWindow,
		Storage:    storage,
		KeyGenerator: func(c fiber.Ctx) string {
			return "session_token:" + keyGenerator(c)
		},
		LimitReached: func(c fiber.Ctx) error {
			return handler.SendTooManyRequests(
				c,
				nil,
				"Too many token exchange requests. Please try again later.",
				handler.ErrTooManyRequests,
			)
		},
	})
}

func sessionTokenPairRateLimitKey(c fiber.Ctx) string {
	deployment := handler.GetDeployment(c)
	serverIP := normalizeRateLimitIP(c.IP())
	realIP := sessionTokenRealIP(c, serverIP)

	return fmt.Sprintf(
		"token_pair:%d:%s:%s",
		deployment.ID,
		rateLimitKeyPart(serverIP),
		rateLimitKeyPart(realIP),
	)
}

func sessionTokenServerRateLimitKey(c fiber.Ctx) string {
	deployment := handler.GetDeployment(c)
	serverIP := normalizeRateLimitIP(c.IP())

	return fmt.Sprintf(
		"token_server:%d:%s:all",
		deployment.ID,
		rateLimitKeyPart(serverIP),
	)
}

func sessionTokenSessionRateLimitKey(c fiber.Ctx) string {
	deployment := handler.GetDeployment(c)

	return fmt.Sprintf(
		"token_session:%d:%s",
		deployment.ID,
		hashRateLimitKeyPart(fmt.Sprintf("%v", c.Locals("session"))),
	)
}

func sessionTokenRealIP(c fiber.Ctx, fallback string) string {
	forwarded := c.Get(wachtForwardedForHeader)
	if ip := firstValidIP(forwarded); ip != "" {
		return ip
	}

	return fallback
}

func firstValidIP(value string) string {
	for _, part := range strings.Split(value, ",") {
		candidate := normalizeRateLimitIP(part)
		if candidate != "" {
			return candidate
		}
	}

	return ""
}

func normalizeRateLimitIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}

	ip := net.ParseIP(strings.Trim(value, "[]"))
	if ip == nil {
		return ""
	}

	return ip.String()
}

func rateLimitKeyPart(value string) string {
	if value == "" {
		return "unknown"
	}

	replacer := strings.NewReplacer(
		":", "_",
		"/", "_",
		" ", "_",
		",", "_",
	)

	return replacer.Replace(value)
}

func hashRateLimitKeyPart(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:16])
}
