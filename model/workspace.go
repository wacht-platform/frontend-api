package model

import "gorm.io/datatypes"

type Workspace struct {
	Model
	OrganizationID  uint                       `json:"-"               gorm:"not null;index;"`
	Name            string                     `json:"name"            gorm:"not null"`
	ImageUrl        string                     `json:"image_url"       gorm:"not null"`
	Description     string                     `json:"description"     gorm:"not null"`
	Roles           []*DeploymentWorkspaceRole `json:"roles"`
	Members         []*WorkspaceMembership     `json:"members"`
	MemberCount     uint32                     `json:"member_count"    gorm:"not null"`
	PublicMetadata  datatypes.JSONMap          `json:"public_metadata" gorm:"not null"`
	PrivateMetadata datatypes.JSONMap          `json:"-"               gorm:"not null"`
}
