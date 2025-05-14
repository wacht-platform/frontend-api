package organization

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
	Domain string `json:"domain" validate:"required,fqdn"`
}

type VerifyDomainRequest struct {
	Domain string `json:"domain" validate:"required,fqdn"`
}

type BillingAddressRequest struct {
	Address    string `json:"address" validate:"required"`
	City       string `json:"city" validate:"required"`
	State      string `json:"state" validate:"required"`
	Country    string `json:"country" validate:"required"`
	PostalCode string `json:"postal_code" validate:"required"`
}

type UpdateBillingAddressRequest struct {
	Address    string `json:"address" validate:"required"`
	City       string `json:"city" validate:"required"`
	State      string `json:"state" validate:"required"`
	Country    string `json:"country" validate:"required"`
	PostalCode string `json:"postal_code" validate:"required"`
}
