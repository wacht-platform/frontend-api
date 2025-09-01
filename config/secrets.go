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

// InitSecrets fetches OAuth credentials from a single JSON secret in Google Secret Manager
func InitSecrets(ctx context.Context, config SecretConfig) error {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create secret manager client: %w", err)
	}
	defer client.Close()

	// Fetch the single JSON secret containing all OAuth credentials
	secretName := "oauth-credentials"
	if config.Prefix != "" {
		secretName = config.Prefix + secretName
	}

	jsonData, err := fetchSecret(ctx, client, config.ProjectID, secretName)
	if err != nil {
		return fmt.Errorf("failed to fetch OAuth credentials secret: %w", err)
	}

	// Parse JSON and set environment variables
	var credentials map[string]string
	if err := json.Unmarshal([]byte(jsonData), &credentials); err != nil {
		return fmt.Errorf("failed to parse OAuth credentials JSON: %w", err)
	}

	// Set each credential as environment variable
	for key, value := range credentials {
		os.Setenv(key, value)
		log.Printf("Loaded %s from Secret Manager", key)
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

