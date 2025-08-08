package entity

import (
	"time"

	"github.com/google/uuid"
)

type OTPType string

const (
	OTPTypeEmailVerification OTPType = "email_verification"
	OTPTypePasswordReset     OTPType = "password_reset"
	OTPTypeLogin             OTPType = "login"
)

type OTP struct {
	ID        uuid.UUID `json:"id" db:"id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
	Code      string    `json:"code" db:"code"`
	Type      OTPType   `json:"type" db:"type"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	Used      bool      `json:"used" db:"used"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}
