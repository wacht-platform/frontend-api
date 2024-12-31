package model

type DeploymentKeyPair struct {
	Model
	DeploymentID uint
	PublicKey    string
	PrivateKey   string
}
