package config

import "github.com/joho/godotenv"

func Init() {
	godotenv.Load()
	InitAwsSession()
}
