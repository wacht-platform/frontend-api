package ai

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wacht-platform/frontend-api/model"
	"gorm.io/gorm"
)

const (
	mcpOAuthStateTTL = 15 * time.Minute
)

func (s *Service) ListActorMcpServers(deploymentID, actorID uint64) ([]ActorMcpServerSummary, error) {
	var servers []model.McpServer
	if err := s.db.
		Where("deployment_id = ?", deploymentID).
		Order("name ASC").
		Find(&servers).Error; err != nil {
		return nil, err
	}

	var connections []model.ActorMcpServerConnection
	if err := s.db.
		Where("deployment_id = ? AND actor_id = ?", deploymentID, actorID).
		Find(&connections).Error; err != nil {
		return nil, err
	}

	connectionByServerID := make(map[uint64]model.ActorMcpServerConnection, len(connections))
	for _, connection := range connections {
		connectionByServerID[connection.McpServerID] = connection
	}

	now := time.Now().UTC()
	result := make([]ActorMcpServerSummary, 0, len(servers))
	for _, server := range servers {
		authType := "none"
		requiresUserConnection := false
		if server.Config.Auth != nil {
			authType = server.Config.Auth.Type
			requiresUserConnection = server.Config.Auth.RequiresUserConnection()
		}

		summary := ActorMcpServerSummary{
			ID:                     server.ID,
			Name:                   server.Name,
			Endpoint:               server.Config.Endpoint,
			AuthType:               authType,
			RequiresUserConnection: requiresUserConnection,
			ConnectionStatus:       "ready",
		}

		if requiresUserConnection {
			summary.ConnectionStatus = "not_connected"
			if connection, ok := connectionByServerID[server.ID]; ok {
				summary.ConnectedAt = connection.ConnectionMetadata.ConnectedAt
				summary.ExpiresAt = connection.ConnectionMetadata.ExpiresAt
				if connection.ConnectionMetadata.ExpiresAt != nil && connection.ConnectionMetadata.ExpiresAt.Before(now) {
					summary.ConnectionStatus = "expired"
				} else {
					summary.ConnectionStatus = "connected"
				}
			}
		}

		result = append(result, summary)
	}

	return result, nil
}

func (s *Service) DisconnectActorMcpServer(deploymentID, actorID, mcpServerID uint64) error {
	return s.db.
		Where("deployment_id = ? AND actor_id = ? AND mcp_server_id = ?", deploymentID, actorID, mcpServerID).
		Delete(&model.ActorMcpServerConnection{}).Error
}

func (s *Service) BuildActorMcpServerConnectURL(
	deployment model.Deployment,
	actorID uint64,
	mcpServerID uint64,
) (string, error) {
	server, err := s.getDeploymentMcpServer(deployment.ID, mcpServerID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", fmt.Errorf("MCP server not found")
		}
		return "", err
	}

	auth := server.Config.Auth
	if auth == nil || !auth.RequiresUserConnection() {
		return "", fmt.Errorf("This MCP server does not require actor consent")
	}
	if strings.TrimSpace(auth.AuthURL) == "" {
		return "", fmt.Errorf("MCP server auth_url is missing")
	}
	if strings.TrimSpace(auth.TokenURL) == "" {
		return "", fmt.Errorf("MCP server token_url is missing")
	}
	if strings.TrimSpace(auth.ClientID) == "" {
		return "", fmt.Errorf("MCP server client_id is missing")
	}

	stateID := uuid.NewString()
	codeVerifier, err := generateRandomBase64URL(32)
	if err != nil {
		return "", err
	}
	codeChallenge := computeCodeChallenge(codeVerifier)
	redirectURI := "https://agentlink.wacht.services/service/mcp/consent/callback"

	statePayload := model.McpOAuthState{
		State:        stateID,
		DeploymentID: deployment.ID,
		ActorID:      actorID,
		McpServerID:  mcpServerID,
		CodeVerifier: codeVerifier,
		ClientID:     auth.ClientID,
		TokenURL:     auth.TokenURL,
		RedirectURI:  redirectURI,
		ExpiresAt:    time.Now().UTC().Add(mcpOAuthStateTTL),
	}
	if strings.TrimSpace(auth.Resource) != "" {
		resource := strings.TrimSpace(auth.Resource)
		statePayload.Resource = &resource
	}

	if err := s.db.Create(&statePayload).Error; err != nil {
		return "", err
	}

	authURL, err := url.Parse(auth.AuthURL)
	if err != nil {
		return "", fmt.Errorf("invalid auth_url")
	}
	query := authURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", auth.ClientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("state", stateID)
	query.Set("code_challenge", codeChallenge)
	query.Set("code_challenge_method", "S256")
	if len(auth.Scopes) > 0 {
		query.Set("scope", strings.Join(auth.Scopes, " "))
	}
	if strings.TrimSpace(auth.Resource) != "" {
		query.Set("resource", strings.TrimSpace(auth.Resource))
	}
	authURL.RawQuery = query.Encode()
	return authURL.String(), nil
}

func (s *Service) getDeploymentMcpServer(deploymentID, mcpServerID uint64) (*model.McpServer, error) {
	var server model.McpServer
	if err := s.db.
		Where("deployment_id = ? AND id = ?", deploymentID, mcpServerID).
		First(&server).Error; err != nil {
		return nil, err
	}
	return &server, nil
}

func generateRandomBase64URL(size int) (string, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func computeCodeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
