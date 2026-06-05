package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v3"
	"github.com/wacht-platform/frontend-api/config"
	"github.com/wacht-platform/frontend-api/database"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/pkg/idgen"
	"github.com/wacht-platform/frontend-api/router"
	"github.com/wacht-platform/frontend-api/service"
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

	// Wire the search-index publisher now that NATS is up. Injected so the database
	// package (where SyncUserWrapper lives) needn't import service (import cycle).
	database.PublishSearchSync = func(userID uint64) {
		if err := service.GetNATS().PublishSearchUserSync(userID); err != nil {
			log.Printf("[search] failed to enqueue sync for user %d: %v", userID, err)
		}
	}

	err = service.InitPrelude()
	if err != nil {
		log.Fatal("Error initializing Prelude: ", err)
	}

	app := fiber.New(fiber.Config{
		JSONEncoder:    json.Marshal,
		JSONDecoder:    json.Unmarshal,
		ErrorHandler:   handler.DefaultErrorHandler,
		TrustProxy:     false,
		ReadBufferSize: 16384,
		BodyLimit:      50 * 1024 * 1024,
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
