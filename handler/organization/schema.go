package organization

type CreateOrgRequest struct {
	Name        string `form:"name" validate:"required"`
	Description string `form:"description"`
}

type UpdateOrgRequest struct {
	Name        string `form:"name" validate:"required"`
	Description string `form:"description"`
}

type InviteMemberRequest struct {
	Email string `form:"email" validate:"required,email"`
	Role  string `form:"role"  validate:"required,oneof=member admin owner"`
}
