package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/config"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/router"
)

func main() {
	config.Env()

	err := database.Connect()
	if err != nil {
		log.Fatal("Error connecting to database: ", err)
	}

	// err = database.Migrate()
	// if err != nil {
	// 	log.Fatal("Error migrating database: ", err)
	// }

	app := fiber.New()
	router.SetupAppRoutes(app)

	log.Fatal(app.Listen(":3000"))
}
