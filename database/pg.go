package database

import (
	"os"

	"github.com/ilabs/wacht-fe/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var Connection *gorm.DB

func InitPgConnection() error {
	dsn := os.Getenv("DATABASE_URL")
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		SkipDefaultTransaction: true,
		// PrepareStmt:            true,
		// Logger: logger.New(log.Default(), logger.Config{
		// 	LogLevel: logger.Info,
		// }),
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
		&model.OrgSettings{},
		&model.AuthSettings{},
		&model.User{},
		&model.Session{},
		&model.UserEmailAddress{},
		&model.DeploymentSocialConnection{},
		&model.SignInAttempt{},
		&model.SocialConnection{},
		&model.SignIn{},
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
		&model.DisplaySettings{},
	)
}
