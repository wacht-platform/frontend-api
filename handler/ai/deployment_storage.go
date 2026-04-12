package ai

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/wacht-platform/frontend-api/config"
	"github.com/wacht-platform/frontend-api/database"
	"gorm.io/gorm"
)

const (
	defaultDeploymentStorageRegion = "auto"
	deploymentStorageNonceSize     = 12
)

type deploymentStorageSettingsRow struct {
	StorageProvider        string  `gorm:"column:storage_provider"`
	StorageBucket          *string `gorm:"column:storage_bucket"`
	StorageRegion          *string `gorm:"column:storage_region"`
	StorageEndpoint        *string `gorm:"column:storage_endpoint"`
	StorageRootPrefix      *string `gorm:"column:storage_root_prefix"`
	StorageForcePathStyle  bool    `gorm:"column:storage_force_path_style"`
	StorageAccessKeyID     *string `gorm:"column:storage_access_key_id"`
	StorageSecretAccessKey *string `gorm:"column:storage_secret_access_key"`
}

type deploymentAgentStorage struct {
	bucket     string
	rootPrefix string
	s3Client   *s3.S3
}

func resolveDeploymentAgentStorage(deploymentID uint64) (*deploymentAgentStorage, error) {
	var row deploymentStorageSettingsRow
	if err := database.Connection.Table("deployment_ai_settings").
		Select([]string{
			"storage_provider",
			"storage_bucket",
			"storage_region",
			"storage_endpoint",
			"storage_root_prefix",
			"storage_force_path_style",
			"storage_access_key_id",
			"storage_secret_access_key",
		}).
		Where("deployment_id = ?", deploymentID).
		Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("deployment storage not configured")
		}
		return nil, err
	}

	if strings.TrimSpace(row.StorageProvider) != "s3" {
		return nil, fmt.Errorf("deployment storage provider must be s3")
	}

	bucket := strings.TrimSpace(derefString(row.StorageBucket))
	endpoint := strings.TrimSpace(derefString(row.StorageEndpoint))
	if bucket == "" || endpoint == "" {
		return nil, fmt.Errorf("deployment storage bucket and endpoint are required")
	}

	accessKeyID, err := decryptDeploymentStorageValue(derefString(row.StorageAccessKeyID))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt deployment storage access key: %w", err)
	}
	secretAccessKey, err := decryptDeploymentStorageValue(derefString(row.StorageSecretAccessKey))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt deployment storage secret key: %w", err)
	}

	region := strings.TrimSpace(derefString(row.StorageRegion))
	if region == "" {
		region = defaultDeploymentStorageRegion
	}
	rootPrefix := strings.Trim(strings.TrimSpace(derefString(row.StorageRootPrefix)), "/")

	sess, err := session.NewSession(&aws.Config{
		Endpoint:         aws.String(endpoint),
		Region:           aws.String(region),
		S3ForcePathStyle: aws.Bool(row.StorageForcePathStyle),
		Credentials:      credentials.NewStaticCredentials(accessKeyID, secretAccessKey, ""),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create deployment storage session: %w", err)
	}

	return &deploymentAgentStorage{
		bucket:     bucket,
		rootPrefix: rootPrefix,
		s3Client:   s3.New(sess),
	}, nil
}

func (s *deploymentAgentStorage) objectKey(relativeKey string) string {
	trimmedKey := strings.TrimLeft(strings.TrimSpace(relativeKey), "/")
	if s.rootPrefix == "" {
		return trimmedKey
	}
	if trimmedKey == "" {
		return s.rootPrefix
	}
	return s.rootPrefix + "/" + trimmedKey
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func decryptDeploymentStorageValue(encrypted string) (string, error) {
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
	if len(combined) < deploymentStorageNonceSize {
		return "", fmt.Errorf("invalid encrypted payload")
	}

	nonce := combined[:deploymentStorageNonceSize]
	ciphertext := combined[deploymentStorageNonceSize:]

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
