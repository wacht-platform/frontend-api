package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/godruoyi/go-snowflake"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type NatsService struct {
	nc *nats.Conn
	js jetstream.JetStream
}

type EmailTaskType string

const (
	EmailVerification       EmailTaskType = "email.send_verification"
	EmailPasswordReset      EmailTaskType = "email.send_password_reset"
	EmailMagicLink          EmailTaskType = "email.send_magic_link"
	EmailSignInNotification EmailTaskType = "email.send_signin_notification"
	EmailPrimaryChange      EmailTaskType = "email.send_primary_change"
	EmailPasswordChange     EmailTaskType = "email.send_password_change"
	EmailPasswordRemove     EmailTaskType = "email.send_password_remove"
	EmailWaitlistSignup     EmailTaskType = "email.send_waitlist_signup"
	EmailOrganizationInvite EmailTaskType = "email.send_organization_invite"
	EmailWorkspaceInvite    EmailTaskType = "email.send_workspace_invite"
	EmailWaitlistInvite     EmailTaskType = "email.send_waitlist_invite"
)

type TaskType string

const (
	TokenCleanup TaskType = "token.cleanup"
)

type NatsTaskMessage struct {
	TaskType string          `json:"task_type"`
	TaskID   string          `json:"task_id"`
	Payload  json.RawMessage `json:"payload"`
}

type VerificationEmailTask struct {
	DeploymentID     uint64 `json:"deployment_id"`
	Recipient        string `json:"recipient"`
	UserID           uint64 `json:"user_id"`
	VerificationCode string `json:"verification_code"`
}

type PasswordResetEmailTask struct {
	DeploymentID uint64 `json:"deployment_id"`
	Recipient    string `json:"recipient"`
	UserID       uint64 `json:"user_id"`
	ResetCode    string `json:"reset_code"`
}

type MagicLinkEmailTask struct {
	DeploymentID uint64 `json:"deployment_id"`
	Recipient    string `json:"recipient"`
	UserID       uint64 `json:"user_id"`
	MagicLink    string `json:"magic_link"`
}

type SignInNotificationTask struct {
	DeploymentID uint64 `json:"deployment_id"`
	Recipient    string `json:"recipient"`
	UserID       uint64 `json:"user_id"`
	SignInID     uint64 `json:"signin_id"`
}

type EmailChangeTask struct {
	DeploymentID uint64 `json:"deployment_id"`
	Recipient    string `json:"recipient"`
	UserID       uint64 `json:"user_id"`
	OldEmail     string `json:"old_email"`
	NewEmail     string `json:"new_email"`
}

type PasswordChangeTask struct {
	DeploymentID uint64 `json:"deployment_id"`
	Recipient    string `json:"recipient"`
	UserID       uint64 `json:"user_id"`
}

type PasswordRemoveTask struct {
	DeploymentID uint64 `json:"deployment_id"`
	Recipient    string `json:"recipient"`
	UserID       uint64 `json:"user_id"`
}

type WaitlistSignupTask struct {
	DeploymentID uint64 `json:"deployment_id"`
	Recipient    string `json:"recipient"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
}

type OrganizationInviteTask struct {
	DeploymentID     uint64 `json:"deployment_id"`
	Recipient        string `json:"recipient"`
	InviterName      string `json:"inviter_name"`
	OrganizationName string `json:"organization_name"`
	InviteLink       string `json:"invite_link"`
}

type WorkspaceInviteTask struct {
	DeploymentID     uint64 `json:"deployment_id"`
	Recipient        string `json:"recipient"`
	InviterName      string `json:"inviter_name"`
	OrganizationName string `json:"organization_name"`
	WorkspaceName    string `json:"workspace_name"`
	InviteLink       string `json:"invite_link"`
}

type WaitlistInviteTask struct {
	DeploymentID uint64 `json:"deployment_id"`
	Recipient    string `json:"recipient"`
	FirstName    string `json:"first_name"`
	InviteLink   string `json:"invite_link"`
}

type TokenCleanupTask struct {
	RotatingTokenID uint64 `json:"rotating_token_id"`
	SessionID       uint64 `json:"session_id"`
}

var natsService *NatsService

func NewNatsService() (*NatsService, error) {
	if natsService != nil {
		return natsService, nil
	}

	natsURL := os.Getenv("NATS_URL")

	nc, err := nats.Connect(natsURL,
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.Timeout(10*time.Second),
		nats.PingInterval(20*time.Second),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
		}),
		nats.ErrorHandler(func(nc *nats.Conn, sub *nats.Subscription, err error) {
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("failed to create JetStream context: %w", err)
	}

	ctx := context.Background()
	streamName := "worker_tasks"
	_, err = js.Stream(ctx, streamName)
	if err != nil {
		_, err = js.CreateStream(ctx, jetstream.StreamConfig{
			Name:      streamName,
			Subjects:  []string{"worker.tasks.>"},
			Retention: jetstream.WorkQueuePolicy,
			Storage:   jetstream.FileStorage,
			MaxAge:    24 * time.Hour,
		})
		if err != nil {
			nc.Close()
			return nil, fmt.Errorf("failed to create stream: %w", err)
		}
	}

	natsService = &NatsService{
		nc: nc,
		js: js,
	}

	return natsService, nil
}

func (s *NatsService) publishTask(ctx context.Context, taskType string, payload interface{}) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	message := NatsTaskMessage{
		TaskType: taskType,
		TaskID:   fmt.Sprintf("%d", snowflake.ID()),
		Payload:  payloadBytes,
	}

	messageBytes, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	subject := fmt.Sprintf("worker.tasks.%s", taskType)
	_, err = s.js.Publish(ctx, subject, messageBytes)
	if err != nil {
		return fmt.Errorf("failed to publish message: %w", err)
	}

	return nil
}

// Email sending methods
func (s *NatsService) SendVerificationEmail(deploymentID, userID uint64, recipient, verificationCode string) error {
	task := VerificationEmailTask{
		DeploymentID:     deploymentID,
		Recipient:        recipient,
		UserID:           userID,
		VerificationCode: verificationCode,
	}
	return s.publishTask(context.Background(), string(EmailVerification), task)
}

func (s *NatsService) SendPasswordResetEmail(deploymentID, userID uint64, recipient, resetCode string) error {
	task := PasswordResetEmailTask{
		DeploymentID: deploymentID,
		Recipient:    recipient,
		UserID:       userID,
		ResetCode:    resetCode,
	}
	return s.publishTask(context.Background(), string(EmailPasswordReset), task)
}

func (s *NatsService) SendMagicLinkEmail(deploymentID, userID uint64, recipient, magicLink string) error {
	task := MagicLinkEmailTask{
		DeploymentID: deploymentID,
		Recipient:    recipient,
		UserID:       userID,
		MagicLink:    magicLink,
	}
	return s.publishTask(context.Background(), string(EmailMagicLink), task)
}

func (s *NatsService) SendSignInNotificationEmail(deploymentID, userID, signInID uint64, recipient string) error {
	task := SignInNotificationTask{
		DeploymentID: deploymentID,
		Recipient:    recipient,
		UserID:       userID,
		SignInID:     signInID,
	}
	return s.publishTask(context.Background(), string(EmailSignInNotification), task)
}

func (s *NatsService) SendPrimaryEmailChangeEmail(deploymentID, userID uint64, recipient, oldEmail, newEmail string) error {
	task := EmailChangeTask{
		DeploymentID: deploymentID,
		Recipient:    recipient,
		UserID:       userID,
		OldEmail:     oldEmail,
		NewEmail:     newEmail,
	}
	return s.publishTask(context.Background(), string(EmailPrimaryChange), task)
}

func (s *NatsService) SendPasswordChangeEmail(deploymentID, userID uint64, recipient string) error {
	task := PasswordChangeTask{
		DeploymentID: deploymentID,
		Recipient:    recipient,
		UserID:       userID,
	}
	return s.publishTask(context.Background(), string(EmailPasswordChange), task)
}

func (s *NatsService) SendPasswordRemoveEmail(deploymentID, userID uint64, recipient string) error {
	task := PasswordRemoveTask{
		DeploymentID: deploymentID,
		Recipient:    recipient,
		UserID:       userID,
	}
	return s.publishTask(context.Background(), string(EmailPasswordRemove), task)
}

func (s *NatsService) SendWaitlistSignupEmail(deploymentID uint64, recipient, firstName, lastName string) error {
	task := WaitlistSignupTask{
		DeploymentID: deploymentID,
		Recipient:    recipient,
		FirstName:    firstName,
		LastName:     lastName,
	}
	return s.publishTask(context.Background(), string(EmailWaitlistSignup), task)
}

func (s *NatsService) SendOrganizationInviteEmail(deploymentID uint64, recipient, inviterName, orgName, inviteLink string) error {
	task := OrganizationInviteTask{
		DeploymentID:     deploymentID,
		Recipient:        recipient,
		InviterName:      inviterName,
		OrganizationName: orgName,
		InviteLink:       inviteLink,
	}
	return s.publishTask(context.Background(), string(EmailOrganizationInvite), task)
}

func (s *NatsService) SendWorkspaceInviteEmail(deploymentID uint64, recipient, inviterName, orgName, workspaceName, inviteLink string) error {
	task := WorkspaceInviteTask{
		DeploymentID:     deploymentID,
		Recipient:        recipient,
		InviterName:      inviterName,
		OrganizationName: orgName,
		WorkspaceName:    workspaceName,
		InviteLink:       inviteLink,
	}
	return s.publishTask(context.Background(), string(EmailWorkspaceInvite), task)
}

func (s *NatsService) SendWaitlistInviteEmail(deploymentID uint64, recipient, firstName, inviteLink string) error {
	task := WaitlistInviteTask{
		DeploymentID: deploymentID,
		Recipient:    recipient,
		FirstName:    firstName,
		InviteLink:   inviteLink,
	}
	return s.publishTask(context.Background(), string(EmailWaitlistInvite), task)
}

func (s *NatsService) ScheduleTokenCleanup(rotatingTokenID, sessionID uint64, delayMinutes int) error {
	task := TokenCleanupTask{
		RotatingTokenID: rotatingTokenID,
		SessionID:       sessionID,
	}
	// TODO: Add delay support if needed
	return s.publishTask(context.Background(), string(TokenCleanup), task)
}

func (s *NatsService) Close() {
	if s.nc != nil && !s.nc.IsClosed() {
		s.nc.Close()
	}
}
