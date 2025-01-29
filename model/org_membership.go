package model

type OrganizationMembership struct {
	Model
	OrganizationID uint               `json:"organization_id"`
	UserID         uint               `json:"user_id"`
	Role           []*OrgnizationRole `json:"role"            gorm:"many2many:org_membership_roles;"`
}
