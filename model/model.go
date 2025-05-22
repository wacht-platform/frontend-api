package model

import (
	"time"
)

type Model struct {
	ID        uint64    `gorm:"primarykey"              json:"id,string"`
	CreatedAt time.Time `gorm:"autoCreateTime;not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime;not null" json:"updated_at"`
}
