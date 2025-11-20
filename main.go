package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
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
		ReadBufferSize:          16384,
	})

	router.Setup(app)

	// Graceful shutdown handling
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Gracefully shutting down...")
		_ = app.Shutdown()
	}()

	if err := app.Listen(":3000"); err != nil {
		log.Panic(err)
	}
}
