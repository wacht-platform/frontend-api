package model

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

type Model struct {
	ID        uint      `gorm:"primarykey" json:"-"`
	IDStr     string    `gorm:"-"          json:"id"`
	CreatedAt time.Time `                  json:"created_at"`
	UpdatedAt time.Time `                  json:"updated_at"`
}

func (m *Model) BeforeCreate(tx *gorm.DB) error {
	m.IDStr = fmt.Sprintf("%d", m.ID)
	return nil
}

func (m *Model) AfterFind(tx *gorm.DB) error {
	m.IDStr = fmt.Sprintf("%d", m.ID)
	return nil
}
