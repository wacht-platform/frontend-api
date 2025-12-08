package model

type DeploymentKeyPair struct {
	Model
	DeploymentID   uint64  `json:"deployment_id"   gorm:"not null;index"`
	PublicKey      string  `json:"public_key"      gorm:"not null"`
	PrivateKey     string  `json:"-"               gorm:"not null"`
	SamlPublicKey  *string `json:"saml_public_key" gorm:"column:saml_public_key"`
	SamlPrivateKey *string `json:"-"               gorm:"column:saml_private_key"`
}
