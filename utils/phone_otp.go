package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ilabs/wacht-fe/config"
	"github.com/ilabs/wacht-fe/database"
)

func VerifyPhoneOTP(deploymentID uint64, phoneNumber, countryCode, code string) (bool, error) {
	cleanPhone := strings.TrimPrefix(phoneNumber, "+")
	cacheKey := fmt.Sprintf("sms_verification:%d:%s:%s", deploymentID, countryCode, cleanPhone)
	verificationID, err := database.Redis.Get(context.Background(), cacheKey).Result()
	if err != nil {
		return false, fmt.Errorf("verification session expired or not found")
	}

	customerID := config.GetEnv("MESSAGE_CENTRAL_CUSTOMER_ID", "")
	authToken := config.GetEnv("MESSAGE_CENTRAL_AUTH_TOKEN", "")

	if customerID == "" || authToken == "" {
		return false, fmt.Errorf("MessageCentral credentials not configured")
	}

	url := fmt.Sprintf(
		"https://cpaas.messagecentral.com/verification/v3/validateOtp?verificationId=%s&code=%s",
		verificationID, code,
	)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("authToken", authToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to call MessageCentral API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Errorf("failed to parse response: %w", err)
	}

	responseCode, ok := result["responseCode"].(float64)
	if !ok || responseCode != 200 {
		return false, nil
	}

	if data, ok := result["data"].(map[string]interface{}); ok {
		if dataResponseCode, ok := data["responseCode"].(string); ok && dataResponseCode == "200" {
			if verificationStatus, ok := data["verificationStatus"].(string); ok {
				return verificationStatus == "VERIFICATION_COMPLETED", nil
			}
		}
	}

	return false, nil
}
