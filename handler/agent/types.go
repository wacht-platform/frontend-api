package agent

import "github.com/ilabs/wacht-fe/model"

type AgentWithIntegrations struct {
	ID           string                   `json:"id"`
	Name         string                   `json:"name"`
	Description  string                   `json:"description"`
	Integrations []model.AgentIntegration `json:"integrations"`
}

type ListAgentsResponse struct {
	Agents []AgentWithIntegrations `json:"agents"`
}

type AgentSessionResponse struct {
	SessionID    string                  `json:"session_id"`
	ContextGroup string                  `json:"context_group"`
	Agents       []AgentWithIntegrations `json:"agents"`
}
