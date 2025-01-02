package model

type OrgSettings struct {
	Model
	DeploymentID       uint   `json:"deployment_id"`
	Enabled            bool   `json:"enabled"`
	IpAllowlistEnabled bool   `json:"ip_allowlist_enabled"`
	MaxAllowedMembers  uint   `json:"max_allowed_members"`
	AllowDeletion      bool   `json:"allow_deletion"`
	CustomRoleEnabled  bool   `json:"custom_role_enabled"`
	DefaultRole        string `json:"default_role"`
}
