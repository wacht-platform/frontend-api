package model

import "gorm.io/datatypes"

type Organization struct {
	Model
	Name            string            `json:"name"`
	ImageUrl        string            `json:"image_url"`
	Description     string            `json:"description"`
	MemberCount     uint32            `json:"member_count"`
	PublicMetadata  datatypes.JSONMap `json:"public_metadata"`
	PrivateMetadata datatypes.JSONMap `json:"-"`
}
