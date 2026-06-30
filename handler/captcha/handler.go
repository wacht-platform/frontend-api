package captcha

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/config"
	"github.com/wacht-platform/frontend-api/handler"
)

func ProxyChallenge(c fiber.Ctx) error {
	target := fmt.Sprintf("%s/%s/challenge", config.Captcha.ServerURL, config.Captcha.SiteKey)
	return proxyToCap(c, target)
}

func VerifyToken(token string) error {
	cfg := config.Captcha
	if token == "" {
		return fmt.Errorf("challenge_token is required")
	}
	target := fmt.Sprintf("%s/%s/siteverify", cfg.ServerURL, cfg.SiteKey)
	body := fmt.Sprintf(`{"secret":"%s","response":"%s"}`, cfg.SecretKey, token)

	resp, err := http.Post(target, "application/json", bytes.NewBufferString(body))
	if err != nil {
		return fmt.Errorf("captcha server unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("captcha server returned %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read captcha response: %w", err)
	}

	if !bytes.Contains(raw, []byte(`"success":true`)) {
		return fmt.Errorf("captcha verification failed")
	}

	return nil
}

func proxyToCap(c fiber.Ctx, target string) error {
	body := c.Body()

	req, err := http.NewRequest(c.Method(), target, bytes.NewReader(body))
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to build proxy request")
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Captcha server unreachable")
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return handler.SendInternalServerError(c, err, "Failed to read captcha response")
	}

	c.Set("Content-Type", "application/json")
	return c.Status(resp.StatusCode).Send(raw)
}
