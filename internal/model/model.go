package model

import (
	"time"
)

type Model struct {
	ID        string
	Metadata  []byte
	CreatedAt time.Time
	UpdatedAt time.Time
}
