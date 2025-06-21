package main

import (
	"log"
	"time"

	"github.com/goccy/go-json"
	"github.com/godruoyi/go-snowflake"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/config"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/router"
)

func main() {
	config.Init()
	snowflake.SetStartTime(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))

	err := database.InitConnection()
	if err != nil {
		log.Fatal("Error connecting to database: ", err)
	}

	app := fiber.New(fiber.Config{
		JSONEncoder:             json.Marshal,
		JSONDecoder:             json.Unmarshal,
		ErrorHandler:            handler.DefaultErrorHandler,
		EnableTrustedProxyCheck: true,
		TrustedProxies:          []string{config.GetEnv("LOAD_BALANCER_IP", "127.0.0.1")},
	})

	router.Setup(app)

	if config.GetEnv("MODE", "production") == "production" {
		log.Fatal(app.Listen(":3000"))
	} else {
		api := fiber.New()
		api.Mount("/api", app)

		log.Fatal(api.Listen(":3000"))
	}

}
