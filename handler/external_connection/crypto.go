package external_connection

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/wacht-platform/frontend-api/config"
)

const nonceSize = 12

func decryptDeploymentSecret(encrypted string) (string, error) {
	encrypted = strings.TrimSpace(encrypted)
	if encrypted == "" {
		return "", fmt.Errorf("value is empty")
	}
	keyHex := strings.TrimSpace(config.GetEnv("ENCRYPTION_KEY", ""))
	if keyHex == "" {
		return "", fmt.Errorf("ENCRYPTION_KEY is required")
	}
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("invalid encryption key hex: %w", err)
	}
	if len(keyBytes) != 32 {
		return "", fmt.Errorf("encryption key must be 32 bytes")
	}

	combined, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("invalid encrypted base64: %w", err)
	}
	if len(combined) < nonceSize {
		return "", fmt.Errorf("invalid encrypted payload")
	}

	nonce := combined[:nonceSize]
	ciphertext := combined[nonceSize:]

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
