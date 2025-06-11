package config

import (
	"os"
	"github.com/joho/godotenv"
)

func Init() {
	godotenv.Load()
	InitAwsSession()
	RegisterHandlebarsHelpers()
}

// GetEnv gets an environment variable with a default value
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
