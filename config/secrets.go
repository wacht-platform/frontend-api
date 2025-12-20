package config

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

type SecretConfig struct {
	ProjectID string
	Prefix    string
}

// InitSecrets fetches credentials from Google Secret Manager
func InitSecrets(ctx context.Context, config SecretConfig) error {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create secret manager client: %w", err)
	}
	defer client.Close()

	// Load OAuth credentials
	if err := loadSecretAsEnvVars(ctx, client, config, "oauth-credentials"); err != nil {
		return fmt.Errorf("failed to load OAuth credentials: %w", err)
	}

	// Load backend API credentials (Abstract API, etc.)
	if err := loadSecretAsEnvVars(ctx, client, config, "backend-credentials"); err != nil {
		log.Printf("Warning: backend-credentials secret not found, skipping: %v", err)
	}

	return nil
}

func loadSecretAsEnvVars(ctx context.Context, client *secretmanager.Client, config SecretConfig, secretName string) error {
	if config.Prefix != "" {
		secretName = config.Prefix + secretName
	}

	jsonData, err := fetchSecret(ctx, client, config.ProjectID, secretName)
	if err != nil {
		return err
	}

	var credentials map[string]string
	if err := json.Unmarshal([]byte(jsonData), &credentials); err != nil {
		return fmt.Errorf("failed to parse %s JSON: %w", secretName, err)
	}

	for key, value := range credentials {
		os.Setenv(key, value)
		log.Printf("Loaded %s from Secret Manager (%s)", key, secretName)
	}

	return nil
}

// fetchSecret retrieves a single secret from Google Secret Manager
func fetchSecret(ctx context.Context, client *secretmanager.Client, projectID, secretName string) (string, error) {
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectID, secretName),
	}

	result, err := client.AccessSecretVersion(ctx, req)
	if err != nil {
		return "", err
	}

	return string(result.Payload.Data), nil
}
