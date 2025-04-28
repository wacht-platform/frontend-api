package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"

	"gorm.io/datatypes"
)

type CustomSigningKey struct {
	Key       string `json:"key"`
	Algorithm string `json:"algorithm"`
}

func (c *CustomSigningKey) Scan(src any) error {
	bytes, ok := src.([]byte)
	if !ok {
		return errors.New(fmt.Sprint("Failed to unmarshal JSONB value:", src))
	}

	result := CustomSigningKey{}
	err := json.Unmarshal(bytes, &result)
	*c = result
	return err
}

func (c *CustomSigningKey) Value() (driver.Value, error) {
	return json.Marshal(c)
}

func (c *CustomSigningKey) GormDataType() string {
	return "jsonb"
}

func (c *CustomSigningKey) GormDBDataType() string {
	return "jsonb"
}

type DeploymentJwtTemplate struct {
	Model
	Name             string           `json:"name"               gorm:"not null"`
	TokenLifetime    int64            `json:"token_lifetime"     gorm:"not null"`
	AllowedClockSkew int64            `json:"allowed_clock_skew" gorm:"not null"`
	CustomSigningKey CustomSigningKey `json:"custom_sign_key"`
	Template         datatypes.JSON   `json:"template"           gorm:"not null"`
	DeploymentID     uint             `json:"deployment_id"      gorm:"not null;index"`
}
