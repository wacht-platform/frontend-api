package model

type OrgMembership struct {
	Model
	OrganizationID uint       `json:"organization_id"`
	UserID         uint       `json:"user_id"`
	Role           []*OrgRole `json:"role"`
}
