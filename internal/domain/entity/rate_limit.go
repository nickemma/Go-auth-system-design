package entity

import (
	"time"
)

type RateLimit struct {
	Key       string    `json:"key" db:"key"`
	Count     int       `json:"count" db:"count"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}
