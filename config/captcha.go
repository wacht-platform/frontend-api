package config

import "os"

type CaptchaConfig struct {
	ServerURL string
	SiteKey   string
	SecretKey string
}

var Captcha CaptchaConfig

func initCaptcha() {
	Captcha = CaptchaConfig{
		ServerURL: GetEnv("CAP_SERVER_URL", "http://127.0.0.1:3000"),
		SiteKey:   os.Getenv("CAP_SITE_KEY"),
		SecretKey: os.Getenv("CAP_SECRET_KEY"),
	}
}
