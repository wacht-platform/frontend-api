package service

import (
	"fmt"
	"time"

	"github.com/ilabs/wacht-fe/database"
	celery "github.com/marselester/gopher-celery"
)

type CeleryService struct {
	app *celery.App
}

type TokenCleanupTask struct {
	RotatingTokenID uint64 `json:"rotating_token_id"`
	SessionID       uint64 `json:"session_id"`
}

type EmailTask struct {
	Type         string `json:"type"`
	DeploymentID uint64 `json:"deployment_id"`
	Recipient    string `json:"recipient"`
}

type SMSTask struct {
	Type         string `json:"type"`
	DeploymentID uint64 `json:"deployment_id"`
	PhoneNumber  string `json:"phone_number"`
}

func NewCeleryService() *CeleryService {
	return &CeleryService{
		app: database.CeleryApp,
	}
}

func (s *CeleryService) ScheduleTokenCleanup(rotatingTokenID, sessionID uint64, delayMinutes int) error {
	if s.app == nil {
		return nil
	}

	task := TokenCleanupTask{
		RotatingTokenID: rotatingTokenID,
		SessionID:       sessionID,
	}

	err := s.app.Delay("token.clean", "token.clean", task)
	if err != nil {
		return fmt.Errorf("failed to schedule token cleanup task: %w", err)
	}

	return nil
}

func (s *CeleryService) SendEmailAsync(taskType string, deploymentID uint64, recipient string) error {
	if s.app == nil {
		return nil
	}

	task := EmailTask{
		Type:         taskType,
		DeploymentID: deploymentID,
		Recipient:    recipient,
	}

	err := s.app.Delay("email.send", "email.send", task)
	if err != nil {
		return fmt.Errorf("failed to schedule email task: %w", err)
	}

	return nil
}

func (s *CeleryService) SendSMSAsync(taskType string, deploymentID uint64, phoneNumber string) error {
	if s.app == nil {
		return nil
	}

	task := SMSTask{
		Type:         taskType,
		DeploymentID: deploymentID,
		PhoneNumber:  phoneNumber,
	}

	err := s.app.Delay("sms.send", "sms.send", task)
	if err != nil {
		return fmt.Errorf("failed to schedule SMS task: %w", err)
	}

	return nil
}
