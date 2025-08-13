package workspace

import "github.com/ilabs/wacht-fe/model"

type CreateWorkspaceRequest struct {
	Name           string `form:"name"            validate:"required"`
	Description    string `form:"description"`
	OrganizationID uint64 `form:"organization_id" validate:"required"`
}

type UpdateWorkspaceRequest struct {
	Name        string `form:"name"        validate:"required"`
	Description string `form:"description"`
}

type InviteWorkspaceMemberRequest struct {
	Email string `form:"email" validate:"required,email"`
	Role  string `form:"role"  validate:"required,oneof=member admin owner"`
}

type WorkspaceMemberQueryResult struct {
	model.WorkspaceMembership
	RolesJSON           string `gorm:"column:roles_json"`
	PublicUserDataJSON  string `gorm:"column:public_user_data_json"`
}
