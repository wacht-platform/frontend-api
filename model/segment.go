package model

type SegmentType string

const (
	SegmentTypeOrganization SegmentType = "organization"
	SegmentTypeWorkspace    SegmentType = "workspace"
	SegmentTypeUser         SegmentType = "user"
)

type Segment struct {
	Model
	DeploymentID uint64      `json:"-" gorm:"not null;index"`
	Name         string      `json:"name" gorm:"not null"`
	Type         SegmentType `json:"type" gorm:"not null"`
}
