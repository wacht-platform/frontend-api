package agent

import "github.com/wacht-platform/frontend-api/model"

type AgentWithIntegrations struct {
	ID           string                   `json:"id"`
	Name         string                   `json:"name"`
	Description  string                   `json:"description"`
	Integrations []model.AgentIntegration `json:"integrations"`
	McpServers   []AgentMcpServer         `json:"mcp_servers"`
}

type AgentMcpServer struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	RequiresConnection bool   `json:"requires_connection"`
}

type ListAgentsResponse struct {
	Agents []AgentWithIntegrations `json:"agents"`
}

type AgentSessionResponse struct {
	SessionID    string                  `json:"session_id"`
	ContextGroup string                  `json:"context_group"`
	Agents       []AgentWithIntegrations `json:"agents"`
}
