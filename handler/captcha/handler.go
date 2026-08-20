package captcha

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/config"
	"github.com/wacht-platform/frontend-api/handler"
)

func ProxyChallenge(c fiber.Ctx) error {
	target := fmt.Sprintf("%s/%s/challenge", config.Captcha.ServerURL, config.Captcha.SiteKey)
	return proxyToCap(c, target)
}

func ProxyRedeem(c fiber.Ctx) error {
	target := fmt.Sprintf("%s/%s/redeem", config.Captcha.ServerURL, config.Captcha.SiteKey)
	return proxyToCap(c, target)
}

type siteVerifyRequest struct {
	Secret   string `json:"secret"`
	Response string `json:"response"`
}

type siteVerifyResponse struct {
	Success bool `json:"success"`
}

var captchaHTTPClient = &http.Client{Timeout: 10 * time.Second}

func VerifyToken(token string) error {
	cfg := config.Captcha
	if token == "" {
		return fmt.Errorf("challenge_token is required")
	}

	payload, err := json.Marshal(siteVerifyRequest{
		Secret:   cfg.SecretKey,
		Response: token,
	})
	if err != nil {
		return fmt.Errorf("failed to encode captcha verification request: %w", err)
	}

	target := fmt.Sprintf("%s/%s/siteverify", cfg.ServerURL, cfg.SiteKey)
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to build captcha verification request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := captchaHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("captcha server unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("captcha server returned %d", resp.StatusCode)
	}

	var result siteVerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode captcha response: %w", err)
	}
	if !result.Success {
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

	resp, err := captchaHTTPClient.Do(req)
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
