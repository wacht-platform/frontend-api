package database

import (
	"log"
	"os"

	"github.com/ilabs/wacht-fe/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var Connection *gorm.DB

func InitPgConnection() error {
	dsn := os.Getenv("DATABASE_URL")
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		SkipDefaultTransaction: true,
		PrepareStmt:            true,
		Logger: logger.New(log.Default(), logger.Config{
			LogLevel: logger.Silent,
		}),
	})
	if err != nil {
		return err
	}

	Connection = db

	return nil
}

func AutoMigratePg() error {
	return Connection.AutoMigrate(
		&model.Project{},
		&model.Deployment{},
		&model.DeploymentOrgSettings{},
		&model.DeploymentAuthSettings{},
		&model.User{},
		&model.Session{},
		&model.UserEmailAddress{},
		&model.DeploymentSocialConnection{},
		&model.SignInAttempt{},
		&model.SocialConnection{},
		&model.Signin{},
		&model.DeploymentKeyPair{},
		&model.RotatingToken{},
		&model.UserPhoneNumber{},
		&model.Organization{},
		&model.OrganizationPermissions{},
		&model.OrgnizationRole{},
		&model.OrganizationMembership{},
		&model.Workspace{},
		&model.WorkspacePermissions{},
		&model.WorkspaceRole{},
		&model.WorkspaceMembership{},
		&model.SignupAttempt{},
		&model.DeploymentDisplaySettings{},
	)
}
