package repository

import (
	"github.com/auth-system/internal/domain/entity"
	"github.com/google/uuid"
)

type ResetTokenRepository interface {
	Create(token *entity.ResetToken) error
	GetByToken(token string) (*entity.ResetToken, error)
	MarkAsUsed(uuid uuid.UUID) error
	DeleteExpired() error
}
