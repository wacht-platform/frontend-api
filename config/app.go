package config

type AppConfig struct {
	Name   string
	Secret string
}

func Get() *AppConfig {
	return &AppConfig{
		Name:   "Wacht",
		Secret: "secret",
	}
}
