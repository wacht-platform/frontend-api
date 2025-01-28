package workspace

type CreateWorkspaceRequest struct {
	Name           string `form:"name"            validate:"required"`
	Description    string `form:"description"`
	OrganizationID uint   `form:"organization_id" validate:"required"`
}

type UpdateWorkspaceRequest struct {
	Name        string `form:"name"        validate:"required"`
	Description string `form:"description"`
}

type InviteWorkspaceMemberRequest struct {
	Email string `form:"email" validate:"required,email"`
	Role  string `form:"role"  validate:"required,oneof=member admin owner"`
}
