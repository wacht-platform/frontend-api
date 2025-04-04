package main

import (
	"log"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/config"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/router"
)

func main() {
	config.Init()

	err := database.InitConnection()
	if err != nil {
		log.Fatal("Error connecting to database: ", err)
	}

	if err = database.AutoMigratePg(); err != nil {
		log.Fatal("Error migrating database: ", err)
	}

	app := fiber.New(fiber.Config{
		JSONEncoder: json.Marshal,
		JSONDecoder: json.Unmarshal,
	})
	router.Setup(app)

	log.Fatal(app.Listen(":3000"))
}
