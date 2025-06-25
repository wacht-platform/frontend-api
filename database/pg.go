package database

import (
	"os"

	"github.com/ilabs/wacht-fe/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/plugin/dbresolver"
)

var Connection *gorm.DB

func InitPgConnection() error {
	dsn := os.Getenv("DATABASE_URL")
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  dsn,
		PreferSimpleProtocol: true,
	}), &gorm.Config{
		SkipDefaultTransaction:                   true,
		PrepareStmt:                              false,
		Logger:                                   logger.Default.LogMode(logger.Info),
		DisableForeignKeyConstraintWhenMigrating: false,
	})
	if err != nil {
		return err
	}

	if os.Getenv("READ_REPLICA") != "" {
		db.Use(dbresolver.Register(dbresolver.Config{
			Replicas: []gorm.Dialector{
				postgres.New(postgres.Config{
					DSN:                  os.Getenv("READ_REPLICA"),
					PreferSimpleProtocol: true,
				}),
			},
		}))
	}

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
		&model.AIKnowledgeBase{},
		&model.AIKnowledgeBaseDocument{},
		&model.AIAgent{},
		&model.AIWorkflow{},
		&model.AIWorkflowExecution{},
		&model.AITool{},
		&model.AIAgentTool{},
		&model.AIAgentWorkflow{},
		&model.AIAgentKnowledgeBase{},
	)
}
