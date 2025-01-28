package model

type OrganizationPermissions struct {
	Model
	OrgRoleID  uint   `json:"org_role_id"`
	Permission string `json:"permission"`
}
