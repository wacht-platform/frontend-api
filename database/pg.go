package database

import (
	"os"

	"github.com/wacht-platform/frontend-api/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var Connection *gorm.DB

func InitPgConnection() error {
	dsn := os.Getenv("DATABASE_PRIMARY_PRIVATE")
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN: dsn,
	}), &gorm.Config{
		SkipDefaultTransaction:                   true,
		Logger:                                   logger.Default.LogMode(logger.Error),
		DisableForeignKeyConstraintWhenMigrating: false,
	})
	if err != nil {
		return err
	}

	pool, _ := db.DB()
	pool.SetMaxIdleConns(3)
	pool.SetMaxOpenConns(5)

	Connection = db

	return nil
}

func AutoMigratePg() error {
	return Connection.AutoMigrate(
		&model.Project{},
		&model.Deployment{},
		&model.DeploymentB2bSettings{},
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
		&model.OrganizationRole{},
		&model.OrganizationMembership{},
		&model.OrgMembershipRoleAssoc{},
		&model.OrganizationInvitation{},
		&model.OrganizationDomain{},
		&model.Workspace{},
		&model.WorkspaceRole{},
		&model.WorkspaceMembership{},
		&model.WorkspaceMembershipRoleAssoc{},
		&model.SignupAttempt{},
		&model.DeploymentUISettings{},
		&model.UserAuthenticator{},
		&model.DeploymentRestrictions{},
		&model.DeploymentJwtTemplate{},
		&model.DeploymentEmailTemplate{},
		&model.DeploymentSmsTemplate{},
		&model.DeploymentInvitation{},
		&model.DeploymentWaitlistUser{},
		&model.AgentThread{},
		&model.UserPasskey{},
		&model.ApiAuthApp{},
		&model.ApiKey{},
		&model.ApiAuthAppSession{},
		&model.ActorExternalConnection{},
		&model.Notification{},
	)
}
