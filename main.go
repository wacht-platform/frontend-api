package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/config"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/pkg/idgen"
	"github.com/ilabs/wacht-fe/router"
	"github.com/ilabs/wacht-fe/service"
)

func main() {
	config.Init()
	idgen.Init()

	err := database.InitConnection()
	if err != nil {
		log.Fatal("Error connecting to database: ", err)
	}

	err = service.InitNATS()
	if err != nil {
		log.Fatal("Error connecting to NATS: ", err)
	}

	err = service.InitPrelude()
	if err != nil {
		log.Fatal("Error initializing Prelude: ", err)
	}

	app := fiber.New(fiber.Config{
		JSONEncoder:             json.Marshal,
		JSONDecoder:             json.Unmarshal,
		ErrorHandler:            handler.DefaultErrorHandler,
		EnableTrustedProxyCheck: true,
		TrustedProxies:          []string{config.GetEnv("LOAD_BALANCER_IP", "127.0.0.1")},
		ReadBufferSize:          16384,
		BodyLimit:               50 * 1024 * 1024,
	})

	router.Setup(app)

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
