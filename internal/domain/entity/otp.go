package entity

import (
	"time"

	"github.com/google/uuid"
)

type OTPType string

const (
	OTPTypeEmailVerification OTPType = "email_verification"
	OTPTypePhoneVerification OTPType = "phone_verification"
	OTPTypePasswordReset     OTPType = "password_reset"
	OTPTypeMFASMS            OTPType = "mfa_sms"
)

type OTP struct {
	ID        uuid.UUID `json:"id" db:"id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
	Code      string    `json:"code" db:"code"`
	Type      OTPType   `json:"type" db:"type"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	Used      bool      `json:"used" db:"used"`
	IPAddress string    `json:"ip_address" db:"ip_address"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}
