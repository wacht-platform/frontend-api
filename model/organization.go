package model

import "gorm.io/datatypes"

type Organization struct {
	Model
	DeploymentID    uint              `json:"deployment_id" gorm:"not null;index"`
	Name            string            `json:"name" gorm:"not null"`
	ImageUrl        string            `json:"image_url" gorm:"not null"`
	Description     string            `json:"description" gorm:"not null"`
	MemberCount     uint32            `json:"member_count" gorm:"not null"`
	PublicMetadata  datatypes.JSONMap `json:"public_metadata" gorm:"not null"`
	PrivateMetadata datatypes.JSONMap `json:"-" gorm:"not null"`
}
