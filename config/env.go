package config

import "github.com/joho/godotenv"

func Env() {
	godotenv.Load()
}
