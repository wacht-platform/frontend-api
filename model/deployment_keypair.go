package model

type DeploymentKeyPair struct {
	Model
	DeploymentID uint64 `json:"deployment_id" gorm:"not null;index"`
	PublicKey    string `json:"public_key"    gorm:"not null"`
	PrivateKey   string `json:"private_key"   gorm:"not null"`
}
