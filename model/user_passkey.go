package model

import (
	"time"

	"github.com/godruoyi/go-snowflake"
	"gorm.io/gorm"
)

// UserPasskey stores WebAuthn credentials for passwordless authentication
type UserPasskey struct {
	Model
	UserID       uint64         `json:"user_id,string"        gorm:"not null;index"`
	Name         string         `json:"name"                  gorm:"not null"` // Friendly name like "MacBook Touch ID"
	CredentialID []byte         `json:"-"                     gorm:"not null;uniqueIndex"`
	PublicKey    []byte         `json:"-"                     gorm:"not null"`
	AAGUID       []byte         `json:"-"`                                        // Authenticator Attestation GUID
	SignCount    uint32         `json:"sign_count"            gorm:"not null"`    // For replay attack prevention
	Transports   []string       `json:"-"                     gorm:"type:text[]"` // usb, nfc, ble, internal
	LastUsedAt   *time.Time     `json:"last_used_at"`
	BackedUp     bool           `json:"backed_up"`   // Whether credential is backed up
	DeviceType   string         `json:"device_type"` // platform or cross-platform
	User         *User          `json:"-"                     gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	DeletedAt    gorm.DeletedAt `json:"-"                gorm:"index"`
}

func NewUserPasskey(userID uint64, name string, credentialID, publicKey, aaguid []byte, signCount uint32, transports []string, backedUp bool, deviceType string) *UserPasskey {
	return &UserPasskey{
		Model: Model{
			ID: snowflake.ID(),
		},
		UserID:       userID,
		Name:         name,
		CredentialID: credentialID,
		PublicKey:    publicKey,
		AAGUID:       aaguid,
		SignCount:    signCount,
		Transports:   transports,
		BackedUp:     backedUp,
		DeviceType:   deviceType,
	}
}

// WebAuthnID implements webauthn.Credential interface
func (p *UserPasskey) WebAuthnID() []byte {
	return p.CredentialID
}
