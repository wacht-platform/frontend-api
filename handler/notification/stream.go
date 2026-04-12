package notification

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/contrib/v3/websocket"
	"github.com/nats-io/nats.go"
	"github.com/wacht-platform/frontend-api/handler"
	"github.com/wacht-platform/frontend-api/model"
	"github.com/wacht-platform/frontend-api/service"
)

type streamNotificationParams struct {
	Channels        []string
	OrganizationIDs []uint64
	WorkspaceIDs    []uint64
}

type streamNotificationMessage struct {
	ID             uint64          `json:"id,string"`
	UserID         *uint64         `json:"user_id,string,omitempty"`
	DeploymentID   uint64          `json:"deployment_id,string"`
	OrganizationID *uint64         `json:"organization_id,string,omitempty"`
	WorkspaceID    *uint64         `json:"workspace_id,string,omitempty"`
	Title          string          `json:"title"`
	Body           string          `json:"body"`
	Severity       string          `json:"severity"`
	CTAs           json.RawMessage `json:"ctas,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

type streamEnvelope struct {
	Type    string                     `json:"type"`
	Data    *streamNotificationMessage `json:"data,omitempty"`
	Message string                     `json:"message,omitempty"`
	Error   string                     `json:"error,omitempty"`
}

func Stream(conn *websocket.Conn) {
	deployment, ok := conn.Locals("deployment").(model.Deployment)
	if !ok {
		_ = conn.WriteJSON(streamEnvelope{Type: "error", Error: "Invalid deployment"})
		return
	}

	session := sessionFromConn(conn)
	if session == nil || session.ActiveSignin == nil || session.ActiveSignin.UserID == nil {
		_ = conn.WriteJSON(streamEnvelope{Type: "error", Error: "Unauthorized"})
		return
	}

	userID := *session.ActiveSignin.UserID
	params := parseStreamNotificationParams(conn)

	natsService := service.GetNATS()
	subject := fmt.Sprintf("notifications.%d.%d", deployment.ID, userID)
	msgCh := make(chan *nats.Msg, 128)

	sub, err := natsService.Conn().ChanSubscribe(subject, msgCh)
	if err != nil {
		_ = conn.WriteJSON(streamEnvelope{Type: "error", Error: "Failed to subscribe to notifications"})
		return
	}
	defer func() {
		_ = sub.Unsubscribe()
		close(msgCh)
	}()

	controlCh := make(chan []byte, 8)
	done := make(chan struct{}, 1)

	go func() {
		defer func() {
			select {
			case done <- struct{}{}:
			default:
			}
		}()

		for {
			messageType, payload, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if messageType != websocket.TextMessage {
				continue
			}

			text := strings.TrimSpace(string(payload))
			if text == "ping" {
				select {
				case controlCh <- []byte("pong"):
				default:
				}
			}
		}
	}()

	if err := conn.WriteJSON(streamEnvelope{
		Type:    "connected",
		Message: "Notification stream connected",
	}); err != nil {
		return
	}

	for {
		select {
		case msg, ok := <-msgCh:
			if !ok {
				return
			}

			var notification streamNotificationMessage
			if err := json.Unmarshal(msg.Data, &notification); err != nil {
				continue
			}

			if !shouldSendStreamNotification(&notification, &params, session) {
				continue
			}

			if err := conn.WriteJSON(streamEnvelope{
				Type: "notification",
				Data: &notification,
			}); err != nil {
				return
			}
		case payload := <-controlCh:
			if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
				return
			}
		case <-done:
			return
		}
	}
}

func sessionFromConn(conn *websocket.Conn) *model.Session {
	if sessionData := conn.Locals("session_data"); sessionData != nil {
		if session, ok := sessionData.(*model.Session); ok {
			return session
		}
	}

	sessionID := conn.Locals("session")
	if sessionID == nil {
		return nil
	}

	session, err := handler.GetSessionFromCacheOrDB(sessionID.(uint64))
	if err != nil {
		return nil
	}

	conn.Locals("session_data", session)
	return session
}

func parseStreamNotificationParams(conn *websocket.Conn) streamNotificationParams {
	req := model.NotificationListRequest{
		Scope:           strings.TrimSpace(conn.Query("scope")),
		Channels:        splitCSV(conn.Query("channels")),
		OrganizationIDs: parseUintCSV(conn.Query("organization_ids")),
		WorkspaceIDs:    parseUintCSV(conn.Query("workspace_ids")),
	}

	return streamNotificationParams{
		Channels:        normalizeChannels(&req),
		OrganizationIDs: req.OrganizationIDs,
		WorkspaceIDs:    req.WorkspaceIDs,
	}
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		values = append(values, value)
	}
	return values
}

func parseUintCSV(raw string) []uint64 {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	values := make([]uint64, 0, len(parts))
	for _, part := range parts {
		value, err := strconv.ParseUint(strings.TrimSpace(part), 10, 64)
		if err != nil {
			continue
		}
		values = append(values, value)
	}
	return values
}

func shouldSendStreamNotification(
	notification *streamNotificationMessage,
	params *streamNotificationParams,
	session *model.Session,
) bool {
	channels := params.Channels
	if len(channels) == 0 {
		channels = []string{"user"}
	}

	for _, channel := range channels {
		switch channel {
		case "user":
			if notification.OrganizationID == nil && notification.WorkspaceID == nil {
				return true
			}
		case "organization":
			if notification.OrganizationID == nil {
				continue
			}
			if len(params.OrganizationIDs) == 0 || containsUint64(params.OrganizationIDs, *notification.OrganizationID) {
				return true
			}
		case "workspace":
			if notification.WorkspaceID == nil {
				continue
			}
			if len(params.WorkspaceIDs) == 0 || containsUint64(params.WorkspaceIDs, *notification.WorkspaceID) {
				return true
			}
		case "current":
			if notification.OrganizationID == nil && notification.WorkspaceID == nil {
				return true
			}
			if session.ActiveSignin == nil {
				continue
			}
			if workspaceMembership := session.ActiveSignin.ActiveWorkspaceMembership; workspaceMembership != nil {
				if notification.WorkspaceID != nil && *notification.WorkspaceID == workspaceMembership.WorkspaceID {
					return true
				}
			}
			if organizationMembership := session.ActiveSignin.ActiveOrganizationMembership; organizationMembership != nil {
				if notification.OrganizationID != nil &&
					*notification.OrganizationID == organizationMembership.OrganizationID &&
					notification.WorkspaceID == nil {
					return true
				}
			}
		case "all":
			return true
		}
	}

	return false
}

func containsUint64(values []uint64, target uint64) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
