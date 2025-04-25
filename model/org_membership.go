package model

type OrganizationMembership struct {
	Model
	OrganizationID uint                          `json:"organization_id" gorm:"not null;index"`
	UserID         uint                          `json:"user_id" gorm:"not null;index"`
	Role           []*DeploymentOrganizationRole `json:"role"            gorm:"many2many:org_membership_roles;"`
}
