package model

import (
	"time"
)

type Model struct {
	ID        uint      `gorm:"primarykey" json:"id,string"`
	CreatedAt time.Time `                  json:"created_at"`
	UpdatedAt time.Time `                  json:"updated_at"`
}
