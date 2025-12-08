package config

import (
	"context"
	"github.com/joho/godotenv"
	"log"
	"os"
)

func Init() {
	godotenv.Load()
	InitAwsSession()
	RegisterHandlebarsHelpers()
	loadSecrets()
}

func loadSecrets() {
	ctx := context.Background()
	secretConfig := SecretConfig{
		ProjectID: GetEnv("GCP_PROJECT_ID", ""),
		Prefix:    GetEnv("SECRET_PREFIX", ""),
	}

	if secretConfig.ProjectID == "" {
		log.Fatal("GCP_PROJECT_ID must be set")
	}

	if err := InitSecrets(ctx, secretConfig); err != nil {
		log.Fatalf("Failed to load secrets from Secret Manager: %v", err)
	}
}

// GetEnv gets an environment variable with a default value
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
