package organization

import "github.com/ilabs/wacht-fe/model"

type CreateOrgRequest struct {
	Name        string `form:"name" validate:"required"`
	Description string `form:"description"`
}

type UpdateOrgRequest struct {
	Name                    *string  `form:"name"`
	Description             *string  `form:"description"`
	WhitelistedIPs          []string `form:"whitelisted_ips"`
	AutoAssignedWorkspaceID *uint64  `form:"auto_assigned_workspace_id,string"`
	EnableIPRestriction     *bool    `form:"enable_ip_restriction"`
	EnforceMFASetup         *bool    `form:"enforce_mfa_setup"`
}

type CreateRoleRequest struct {
	Name        string   `form:"name,min=2,max=100"`
	Permissions []string `form:"permissions"`
}

type InviteMemberRequest struct {
	Email           string  `form:"email" validate:"required,email"`
	RoleID          *uint64 `form:"role_id,string"`
	WorkspaceID     *uint64 `form:"workspace_id,string"`
	WorkspaceRoleID *uint64 `form:"workspace_role_id,string"`
}

type AddDomainRequest struct {
	Domain string `form:"domain" validate:"required,fqdn"`
}

type VerifyDomainRequest struct {
	Domain string `form:"domain" validate:"required,fqdn"`
}

type OrganizationMemberQueryResult struct {
	model.OrganizationMembership
	RolesJSON string `gorm:"column:roles_json"`
	UserJSON  string `gorm:"column:user_json"`
}

type AcceptInvitationRequest struct {
	Token string `json:"token" validate:"required"`
}

type AcceptInvitationResponse struct {
	Organization    OrganizationInfo `json:"organization,omitempty"`
	Workspace       *WorkspaceInfo   `json:"workspace,omitempty"`
	SigninID        string           `json:"signin_id,omitempty"`
	AlreadyMember   bool             `json:"already_member,omitempty"`
	Message         string           `json:"message,omitempty"`
	RequiresSignin  bool             `json:"requires_signin,omitempty"`
	InvitedEmail    string           `json:"invited_email,omitempty"`
	ErrorCode       string           `json:"error_code,omitempty"`
}

type OrganizationInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type WorkspaceInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
