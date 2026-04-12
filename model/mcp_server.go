package model

import "time"

type McpServer struct {
	ID           uint64          `json:"id,string" gorm:"primarykey"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
	DeploymentID uint64          `json:"deployment_id,string" gorm:"index;not null"`
	Name         string          `json:"name" gorm:"not null"`
	Config       McpServerConfig `json:"config" gorm:"type:jsonb;serializer:json;not null"`
}

func (McpServer) TableName() string {
	return "mcp_servers"
}

type McpServerConfig struct {
	Endpoint string            `json:"endpoint"`
	Auth     *McpServerAuth    `json:"auth,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
}

type McpServerAuth struct {
	Type         string   `json:"type"`
	AuthToken    string   `json:"auth_token,omitempty"`
	ClientID     string   `json:"client_id,omitempty"`
	ClientSecret string   `json:"client_secret,omitempty"`
	AuthURL      string   `json:"auth_url,omitempty"`
	TokenURL     string   `json:"token_url,omitempty"`
	RegisterURL  string   `json:"register_url,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	Resource     string   `json:"resource,omitempty"`
}

func (a *McpServerAuth) RequiresUserConnection() bool {
	if a == nil {
		return false
	}
	return a.Type == "oauth_authorization_code_public_pkce" ||
		a.Type == "oauth_authorization_code_confidential_pkce"
}

type McpConnectionMetadata struct {
	AuthType      string     `json:"auth_type"`
	AccessToken   string     `json:"access_token"`
	RefreshToken  *string    `json:"refresh_token,omitempty"`
	TokenType     *string    `json:"token_type,omitempty"`
	Scope         *string    `json:"scope,omitempty"`
	TokenURL      *string    `json:"token_url,omitempty"`
	Resource      *string    `json:"resource,omitempty"`
	OAuthClientID *string    `json:"oauth_client_id,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	ConnectedAt   *time.Time `json:"connected_at,omitempty"`
}
