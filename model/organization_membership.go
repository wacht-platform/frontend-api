package model

type OrganizationMembership struct {
	Model
	OrganizationID uint                `json:"-"            gorm:"not null;index"`
	Organization   Organization        `json:"organization" gorm:"foreignKey:OrganizationID"`
	UserID         uint                `json:"user_id"      gorm:"not null;index"`
	User           PublicUserData      `json:"user" gorm:"foreignKey:UserID"`
	Roles          []*OrganizationRole `json:"roles"  gorm:"many2many:org_membership_roles;"`
}

type PublicUserData struct {
	Model
	FirstName             string            `json:"first_name"                      gorm:"not null"`
	HasProfilePicture     bool              `json:"has_profile_picture"             gorm:"not null"`
	ProfilePictureURL     string            `json:"profile_picture_url"             gorm:"not null"`
	LastName              string            `json:"last_name"                       gorm:"not null"`
	Username              string            `json:"username"                        gorm:"not null"`
	Availability          UserAvailability  `json:"availability"                    gorm:"default:away;not null"`
	PrimaryEmailAddressID *uint             `json:"-"`
	PrimaryPhoneNumberID  *uint             `json:"-"`
	PrimaryPhoneNumber    *UserPhoneNumber  `json:"primary_phone_number" gorm:"foreignKey:ID;references:ID"`
	PrimaryEmailAddress   *UserEmailAddress `json:"primary_email_address" gorm:"foreignKey:ID;references:ID"`
}

func (PublicUserData) TableName() string {
	return "users"
}
