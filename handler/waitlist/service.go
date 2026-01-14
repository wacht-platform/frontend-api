package waitlist

import (
	"log"

	"github.com/ilabs/wacht-fe/database"
	"github.com/ilabs/wacht-fe/handler"
	"github.com/ilabs/wacht-fe/model"
	"github.com/ilabs/wacht-fe/pkg/idgen"
	"github.com/ilabs/wacht-fe/service"
	"gorm.io/gorm"
)

type WaitlistService struct {
	db   *gorm.DB
	nats *service.NatsService
}

func NewWaitlistService() *WaitlistService {
	natsService := service.GetNATS()

	return &WaitlistService{
		db:   database.Connection,
		nats: natsService,
	}
}

func (s *WaitlistService) ValidateJoinWaitlistRequest(
	b *JoinWaitlistRequest,
	d model.Deployment,
) error {
	if d.AuthSettings.FirstName.Required && b.FirstName == "" {
		return handler.ErrRequiredField("First name")
	}
	if d.AuthSettings.LastName.Required && b.LastName == "" {
		return handler.ErrRequiredField("Last name")
	}
	if b.Email == "" {
		return handler.ErrRequiredField("Email address")
	}
	return nil
}

func (s *WaitlistService) CheckEmailExistsInWaitlist(email string, deploymentID uint64) bool {
	var count int64
	s.db.Model(&model.DeploymentWaitlistUser{}).
		Where("deployment_id = ? AND email_address = ?", deploymentID, email).
		Count(&count)
	return count > 0
}

func (s *WaitlistService) CheckUserEmailExists(email string, deploymentID uint64) bool {
	var count int64
	s.db.Model(&model.UserEmailAddress{}).
		Joins("JOIN users ON users.id = user_email_addresses.user_id").
		Where("users.deployment_id = ? AND user_email_addresses.email_address = ?", deploymentID, email).
		Count(&count)
	return count > 0
}

func (s *WaitlistService) CreateWaitlistEntry(
	b *JoinWaitlistRequest,
	deploymentID uint64,
) (*model.DeploymentWaitlistUser, error) {
	deploymentIDUint := uint(deploymentID)
	entry := &model.DeploymentWaitlistUser{
		Model: model.Model{
			ID: idgen.NextID(),
		},
		DeploymentID: &deploymentIDUint,
		EmailAddress: b.Email,
		FirstName:    b.FirstName,
		LastName:     b.LastName,
	}

	if err := s.db.Create(entry).Error; err != nil {
		return nil, err
	}

	if err := s.nats.SendWaitlistSignupEmail(deploymentID, b.Email, b.FirstName, b.LastName); err != nil {
		log.Printf("Failed to send waitlist signup email to %s: %v", b.Email, err)
	}

	return entry, nil
}
