package model

type OrgSettings struct {
	Model
	DeploymentID       uint
	Enabled            bool
	IpAllowlistEnabled bool
	MaxAllowedMembers  uint
	AllowDeletion      bool
	CustomRoleEnabled  bool
	DefaultRole        string
}
