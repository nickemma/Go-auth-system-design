package repository

import (
	"github.com/auth-system/internal/domain/entity"
	"github.com/google/uuid"
)

type OTPRepository interface {
	Create(otp *entity.OTP) error
	GetByCode(code string, otpType entity.OTPType) (*entity.OTP, error)
	GetByUserID(userID uuid.UUID, otpType entity.OTPType) (*entity.OTP, error)
	Update(otp *entity.OTP) error
	DeleteExpired() error
}
