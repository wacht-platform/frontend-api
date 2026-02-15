package config

import (
	"os"

	"github.com/joho/godotenv"
)

func Init() {
	godotenv.Load()
	initR2Session()
	initAgentStorageSession()
}

func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
