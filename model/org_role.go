package model

type OrgnizationRole struct {
	Model
	Name        string                     `json:"name"`
	Permissions []*OrganizationPermissions `json:"permissions" gorm:"many2many:org_role_permissions;"`
}
