package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ilabs/wacht-fe/pkg/idgen"
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
	EmailPrimaryChange      EmailTaskType = "email.send_email_change_notification"
	EmailPasswordChange     EmailTaskType = "email.send_password_change_notification"
	EmailPasswordRemove     EmailTaskType = "email.send_password_remove_notification"
	EmailWaitlistSignup     EmailTaskType = "email.send_waitlist_signup"
	EmailOrganizationInvite EmailTaskType = "email.send_organization_membership_invite"
	EmailWorkspaceInvite    EmailTaskType = "email.send_workspace_invite"
	EmailWaitlistInvite     EmailTaskType = "email.send_waitlist_approval"
)

type SMSTaskType string

const (
	SMSOTPVerification SMSTaskType = "sms.send_otp"
)

type TaskType string

const (
	TokenCleanup TaskType = "token.clean"
)

type BillingTaskType string

const (
	BillingEvent BillingTaskType = "billing.event"
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
	IPAddress        string `json:"ip_address"`
	UserAgent        string `json:"user_agent"`
}

type PasswordResetEmailTask struct {
	DeploymentID uint64 `json:"deployment_id"`
	Recipient    string `json:"recipient"`
	UserID       uint64 `json:"user_id"`
	ResetCode    string `json:"reset_code"`
	IPAddress    string `json:"ip_address"`
	UserAgent    string `json:"user_agent"`
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

type SMSOTPTask struct {
	DeploymentID uint64 `json:"deployment_id"`
	PhoneNumber  string `json:"phone_number"`
	UserID       uint64 `json:"user_id"`
	CountryCode  string `json:"country_code"`
}

type WebhookEventTask struct {
	DeploymentID uint64                 `json:"deployment_id"`
	EventType    string                 `json:"event_type"`
	EventPayload map[string]interface{} `json:"event_payload"`
	TriggeredAt  time.Time              `json:"triggered_at"`
}

type AnalyticsEventTask struct {
	DeploymentID   uint64    `json:"deployment_id"`
	UserID         *uint64   `json:"user_id"`
	EventType      string    `json:"event_type"`
	UserName       *string   `json:"user_name"`
	UserIdentifier *string   `json:"user_identifier"`
	AuthMethod     *string   `json:"auth_method"`
	Timestamp      time.Time `json:"timestamp"`
	IPAddress      *string   `json:"ip_address"`
}

type BillingEventTask struct {
	DeploymentID uint64 `json:"deployment_id"`
	EventType    string `json:"event_type"`
	ResourceID   uint64 `json:"resource_id"`
}

var natsService *NatsService

func InitNATS() error {
	if natsService != nil {
		return nil
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
		return fmt.Errorf("failed to connect to NATS: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return fmt.Errorf("failed to create JetStream context: %w", err)
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
			return fmt.Errorf("failed to create stream: %w", err)
		}
	}

	natsService = &NatsService{
		nc: nc,
		js: js,
	}

	return nil
}

func GetNATS() *NatsService {
	if natsService == nil {
		panic("NATS service not initialized")
	}
	return natsService
}

func (s *NatsService) publishTask(ctx context.Context, taskType string, payload interface{}) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	message := NatsTaskMessage{
		TaskType: taskType,
		TaskID:   fmt.Sprintf("%d", idgen.NextID()),
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
func (s *NatsService) SendVerificationEmail(
	deploymentID, userID uint64,
	recipient, verificationCode, ipAddress, userAgent string,
) error {
	task := VerificationEmailTask{
		DeploymentID:     deploymentID,
		Recipient:        recipient,
		UserID:           userID,
		VerificationCode: verificationCode,
		IPAddress:        ipAddress,
		UserAgent:        userAgent,
	}
	return s.publishTask(context.Background(), string(EmailVerification), task)
}

func (s *NatsService) SendPasswordResetEmail(
	deploymentID, userID uint64,
	recipient, resetCode, ipAddress, userAgent string,
) error {
	task := PasswordResetEmailTask{
		DeploymentID: deploymentID,
		Recipient:    recipient,
		UserID:       userID,
		ResetCode:    resetCode,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
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

func (s *NatsService) SendPrimaryEmailChangeEmail(
	deploymentID, userID uint64,
	recipient, oldEmail, newEmail string,
) error {
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

func (s *NatsService) SendOrganizationInviteEmail(
	deploymentID uint64,
	recipient, inviterName, orgName, inviteLink string,
) error {
	task := OrganizationInviteTask{
		DeploymentID:     deploymentID,
		Recipient:        recipient,
		InviterName:      inviterName,
		OrganizationName: orgName,
		InviteLink:       inviteLink,
	}
	return s.publishTask(context.Background(), string(EmailOrganizationInvite), task)
}

func (s *NatsService) SendWorkspaceInviteEmail(
	deploymentID uint64,
	recipient, inviterName, orgName, workspaceName, inviteLink string,
) error {
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

	return s.publishTask(context.Background(), string(TokenCleanup), task)
}

func (s *NatsService) SendOTPSMS(deploymentID, userID uint64, phoneNumber, countryCode string) error {
	task := SMSOTPTask{
		DeploymentID: deploymentID,
		PhoneNumber:  phoneNumber,
		UserID:       userID,
		CountryCode:  countryCode,
	}
	return s.publishTask(context.Background(), string(SMSOTPVerification), task)
}

func (s *NatsService) PublishWebhookEvent(deploymentID uint64, eventType string, payload map[string]interface{}) error {
	task := WebhookEventTask{
		DeploymentID: deploymentID,
		EventType:    eventType,
		EventPayload: payload,
		TriggeredAt:  time.Now(),
	}
	return s.publishTask(context.Background(), "webhook.event", task)
}

func (s *NatsService) PublishAnalyticsEvent(
	deploymentID uint64,
	userID *uint64,
	eventType string,
	userName, userIdentifier, authMethod, ipAddress *string,
) error {
	task := AnalyticsEventTask{
		DeploymentID:   deploymentID,
		UserID:         userID,
		EventType:      eventType,
		UserName:       userName,
		UserIdentifier: userIdentifier,
		AuthMethod:     authMethod,
		Timestamp:      time.Now(),
		IPAddress:      ipAddress,
	}
	return s.publishTask(context.Background(), "analytics.event", task)
}

func (s *NatsService) PublishBillingEvent(deploymentID, resourceID uint64, eventType string) error {
	task := BillingEventTask{
		DeploymentID: deploymentID,
		EventType:    eventType,
		ResourceID:   resourceID,
	}
	return s.publishTask(context.Background(), string(BillingEvent), task)
}

// Agent execution types
type AgentExecutionRequest struct {
	DeploymentID   string  `json:"deployment_id"`
	ContextID      string  `json:"context_id"`
	AgentID        *string `json:"agent_id,omitempty"`
	AgentName      *string `json:"agent_name,omitempty"`
	Type           string  `json:"type"`
	ConversationID string  `json:"conversation_id,omitempty"`
}

func (s *NatsService) PublishAgentExecution(
	ctx context.Context,
	deploymentID, contextID uint64,
	agentID *int64,
	conversationID uint64,
	executionType string,
) error {
	var agentIDStr *string
	if agentID != nil {
		str := fmt.Sprintf("%d", *agentID)
		agentIDStr = &str
	}

	req := AgentExecutionRequest{
		DeploymentID:   fmt.Sprintf("%d", deploymentID),
		ContextID:      fmt.Sprintf("%d", contextID),
		AgentID:        agentIDStr,
		Type:           executionType,
		ConversationID: fmt.Sprintf("%d", conversationID),
	}

	return s.publishTask(ctx, "agent.execution_request", req)
}

// PublishAgentExecutionWithResult publishes a platform function result execution request
func (s *NatsService) PublishAgentExecutionWithResult(
	ctx context.Context,
	deploymentID, contextID uint64,
	agentID *int64,
	executionID string,
	result map[string]interface{},
) error {
	var agentIDStr *string
	if agentID != nil {
		str := fmt.Sprintf("%d", *agentID)
		agentIDStr = &str
	}

	req := AgentExecutionRequestWithResult{
		DeploymentID: fmt.Sprintf("%d", deploymentID),
		ContextID:    fmt.Sprintf("%d", contextID),
		AgentID:      agentIDStr,
		Type:         "platform_function_result",
		ExecutionID:  executionID,
		Result:       result,
	}

	return s.publishTask(ctx, "agent.execution_request", req)
}

type AgentExecutionRequestWithResult struct {
	DeploymentID string                 `json:"deployment_id"`
	ContextID    string                 `json:"context_id"`
	AgentID      *string                `json:"agent_id,omitempty"`
	AgentName    *string                `json:"agent_name,omitempty"`
	Type         string                 `json:"type"`
	ExecutionID  string                 `json:"execution_id"`
	Result       map[string]interface{} `json:"result"`
}

func (s *NatsService) PublishRateLimit(payload []byte) error {
	return s.nc.Publish("rate_limit.inc", payload)
}

func (s *NatsService) SubscribeToRateLimits(ch chan []byte) {
	s.nc.Subscribe("rate_limit.inc", func(m *nats.Msg) {
		ch <- m.Data
	})
}

func (s *NatsService) GetRateLimitKV(ctx context.Context) (jetstream.KeyValue, error) {
	kv, err := s.js.KeyValue(ctx, "rate_limits")
	if err != nil {
		kv, err = s.js.CreateKeyValue(ctx, jetstream.KeyValueConfig{
			Bucket: "rate_limits",
			TTL:    1 * time.Minute,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create key value bucket: %w", err)
		}
	}
	return kv, nil
}

func (s *NatsService) Close() {
	if s.nc != nil && !s.nc.IsClosed() {
		s.nc.Close()
	}
}
