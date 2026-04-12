package model

import "time"

type McpOAuthState struct {
	State        string    `json:"state" gorm:"primaryKey;type:text"`
	DeploymentID uint64    `json:"deployment_id,string" gorm:"not null"`
	ActorID      uint64    `json:"actor_id,string" gorm:"not null"`
	McpServerID  uint64    `json:"mcp_server_id,string" gorm:"not null"`
	CodeVerifier string    `json:"code_verifier" gorm:"type:text;not null"`
	ClientID     string    `json:"client_id" gorm:"type:text;not null"`
	TokenURL     string    `json:"token_url" gorm:"type:text;not null"`
	RedirectURI  string    `json:"redirect_uri" gorm:"type:text;not null"`
	Resource     *string   `json:"resource,omitempty" gorm:"type:text"`
	ExpiresAt    time.Time `json:"expires_at" gorm:"not null"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (McpOAuthState) TableName() string {
	return "mcp_oauth_states"
}
