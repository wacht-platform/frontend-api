package model

import "gorm.io/datatypes"

type OrgMembershipRoleAssoc struct {
	OrganizationMembershipID uint64 `gorm:"primaryKey;index"`
	OrganizationRoleID       uint64 `gorm:"primaryKey"`
	OrganizationID           uint64 `gorm:"not null;index"`
}

func (OrgMembershipRoleAssoc) TableName() string {
	return "organization_membership_roles"
}

type OrganizationMembership struct {
	Model
	OrganizationID         uint64                   `json:"-"                                 gorm:"not null;index;index:organization_membership_organization_id_user_id_idx,unique"`
	Organization           PublicOrganizationData   `json:"organization"                      gorm:"foreignKey:OrganizationID"`
	UserID                 uint64                   `json:"user_id,string"                    gorm:"not null;index;index:organization_membership_organization_id_user_id_idx,unique"`
	User                   *PublicUserData          `json:"user,omitempty"                    gorm:"foreignKey:UserID"`
	Roles                  []*OrganizationRole      `json:"roles"                             gorm:"many2many:organization_membership_roles;joinForeignKey:OrganizationMembershipID;JoinReferences:OrganizationRoleID;References:ID;foreignKey:ID"`
	RoleAssociations       []OrgMembershipRoleAssoc `json:"-"                                 gorm:"foreignKey:OrganizationMembershipID;references:ID"`
	PublicMetadata         datatypes.JSONMap        `json:"public_metadata"                   gorm:"not null"`
	EligibilityRestriction *EligibilityRestriction  `json:"eligibility_restriction,omitempty" gorm:"-"`
}
