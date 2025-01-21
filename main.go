package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/ilabs/wacht-fe/config"
	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/router"
	"github.com/ilabs/wacht-fe/utils"
)

func main() {
	config.LoadEnv()

	err := database.InitConnection()
	if err != nil {
		log.Fatal("Error connecting to database: ", err)
	}

	if err = database.AutoMigratePg(); err != nil {
		log.Fatal("Error migrating database: ", err)
	}

	app := fiber.New()
	router.Setup(app)

	log.Fatal(app.Listen(":3000"))

	url := utils.GenerateVerificationUrl(model.SSOProviderX, model.SignInAttempt{})
	log.Println(url)
}
