package model

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

type McpServerAuthType string

const (
	McpServerAuthTypeToken                                  McpServerAuthType = "token"
	McpServerAuthTypeOAuthClientCredentials                 McpServerAuthType = "oauth_client_credentials"
	McpServerAuthTypeOAuthAuthorizationCodePublicPKCE       McpServerAuthType = "oauth_authorization_code_public_pkce"
	McpServerAuthTypeOAuthAuthorizationCodeConfidentialPKCE McpServerAuthType = "oauth_authorization_code_confidential_pkce"
)

type McpServerAuthConfig struct {
	Type McpServerAuthType `json:"type"`

	AuthToken    *string  `json:"auth_token,omitempty"`
	ClientID     *string  `json:"client_id,omitempty"`
	ClientSecret *string  `json:"client_secret,omitempty"`
	TokenURL     *string  `json:"token_url,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	AuthURL      *string  `json:"auth_url,omitempty"`
	RegisterURL  *string  `json:"register_url,omitempty"`
	Resource     *string  `json:"resource,omitempty"`
}

type McpServerConfig struct {
	Endpoint string               `json:"endpoint"`
	Auth     *McpServerAuthConfig `json:"auth,omitempty"`
	Headers  map[string]string    `json:"headers,omitempty"`
}

func (c *McpServerConfig) Scan(src any) error {
	bytes, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("failed to unmarshal MCP server config: %T", src)
	}

	var out McpServerConfig
	if err := json.Unmarshal(bytes, &out); err != nil {
		return err
	}

	*c = out
	return nil
}

func (c McpServerConfig) Value() (driver.Value, error) {
	return json.Marshal(c)
}

func (McpServerConfig) GormDataType() string {
	return "jsonb"
}

type McpServer struct {
	Model
	DeploymentID uint64          `json:"deployment_id,string" gorm:"not null;index"`
	Name         string          `json:"name" gorm:"not null"`
	Config       McpServerConfig `json:"config" gorm:"type:jsonb"`
}

func (McpServer) TableName() string {
	return "mcp_servers"
}
