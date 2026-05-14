package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/wacht-platform/frontend-api/config"
)

const encryptionNonceSize = 12

func EncryptAtRest(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	gcm, err := newEncryptionGCM()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, encryptionNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	combined := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(combined), nil
}

// DecryptAtRest reverses EncryptAtRest. Returns an error on invalid base64,
// short payload, or auth-tag mismatch. Empty input returns empty output so
// nullable columns round-trip cleanly.
func DecryptAtRest(encrypted string) (string, error) {
	encrypted = strings.TrimSpace(encrypted)
	if encrypted == "" {
		return "", nil
	}
	combined, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("invalid encrypted base64: %w", err)
	}
	if len(combined) < encryptionNonceSize {
		return "", errors.New("invalid encrypted payload")
	}
	gcm, err := newEncryptionGCM()
	if err != nil {
		return "", err
	}
	nonce := combined[:encryptionNonceSize]
	ciphertext := combined[encryptionNonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func newEncryptionGCM() (cipher.AEAD, error) {
	keyHex := strings.TrimSpace(config.GetEnv("ENCRYPTION_KEY", ""))
	if keyHex == "" {
		return nil, errors.New("ENCRYPTION_KEY is required")
	}
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid encryption key hex: %w", err)
	}
	if len(keyBytes) != 32 {
		return nil, errors.New("encryption key must be 32 bytes (64 hex characters)")
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
