package database

import (
	"os"
	"time"

	"github.com/ilabs/wacht-fe/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var Connection *gorm.DB

func InitPgConnection() error {
	dsn := os.Getenv("DATABASE_URL")
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		SkipDefaultTransaction: true,
		PrepareStmt:            true,
		// Logger:                 logger.Default.LogMode(logger.Silent),
		// DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		return err
	}

	pgDB, err := db.DB()
	if err != nil {
		return err
	}

	pgDB.SetConnMaxIdleTime(time.Hour)
	pgDB.SetConnMaxLifetime(24 * time.Hour)
	pgDB.SetMaxIdleConns(100)

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
		&model.OrganizationBillingAddress{},
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
	)
}
