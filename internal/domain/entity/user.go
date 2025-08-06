package entity

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID              uuid.UUID `json:"id" db:"id"`
	Email           string    `json:"email" db:"email"`
	Password        string    `json:"-" db:"password"`
	FirstName       string    `json:"first_name" db:"first_name"`
	LastName        string    `json:"last_name" db:"last_name"`
	IsEmailVerified bool      `json:"is_email_verified" db:"is_email_verified"`
	IsMFAEnabled    bool      `json:"is_mfa_enabled" db:"is_mfa_enabled"`
	MFASecret       string    `json:"-" db:"mfa_secret"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time `json:"updated_at" db:"updated_at"`
}
