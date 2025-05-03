package model

type OrganizationMembership struct {
	Model
	OrganizationID uint                `json:"-"            gorm:"not null;index"`
	Organization   Organization        `json:"organization" gorm:"foreignKey:OrganizationID"`
	UserID         uint                `json:"user_id"      gorm:"not null;index"`
	Role           []*OrganizationRole `json:"role"  gorm:"many2many:org_membership_roles;"`
}
