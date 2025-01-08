package model

type OrgRole struct {
	Model
	Name        string                `json:"name"`
	Permissions []*OrgRolePermissions `json:"permissions"`
}
