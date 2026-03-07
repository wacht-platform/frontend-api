package workspace

import "github.com/wacht-platform/frontend-api/model"

type CreateWorkspaceRequest struct {
	Name           string `form:"name"            validate:"required"`
	Description    string `form:"description"`
	OrganizationID uint64 `form:"organization_id" validate:"required"`
}

type UpdateWorkspaceRequest struct {
	Name                string   `form:"name"                  validate:"required"`
	Description         string   `form:"description"`
	EnforceMFASetup     *bool    `form:"enforce_2fa"`
	EnableIPRestriction *bool    `form:"enable_ip_restriction"`
	WhitelistedIPs      []string `form:"whitelisted_ips"`
}

type InviteWorkspaceMemberRequest struct {
	Email string `form:"email" validate:"required,email"`
	Role  string `form:"role"  validate:"required,oneof=member admin owner"`
}

type WorkspaceMemberQueryResult struct {
	model.WorkspaceMembership
	RolesJSON          string `gorm:"column:roles_json"`
	PublicUserDataJSON string `gorm:"column:user_json"`
	PublicMetadataJSON string `gorm:"column:public_metadata_json"`
}
