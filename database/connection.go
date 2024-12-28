package database

import (
	"os"

	"github.com/ilabs/wacht-fe/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var Connection *gorm.DB

func Connect() error {
	dsn := os.Getenv("DATABASE_URL")
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		SkipDefaultTransaction: true,
		// PrepareStmt:            true,
	})
	if err != nil {
		return err
	}

	Connection = db

	return nil
}

func Migrate() error {
	return Connection.AutoMigrate(
		&model.Project{},
		&model.Deployment{},
		&model.OrgSettings{},
		&model.AuthSettings{},
		&model.User{},
		&model.Session{},
		&model.UserEmailAddress{},
		&model.SSOConnection{},
		&model.SignInAttempt{},
	)
}
