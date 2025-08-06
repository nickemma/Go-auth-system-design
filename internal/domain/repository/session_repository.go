package repository

import (
	"github.com/auth-system/internal/domain/entity"
	"github.com/google/uuid"
)

type SessionRepository interface {
	Create(session *entity.Session) error
	GetByToken(token string) (*entity.Session, error)
	GetByUserID(userID uuid.UUID) ([]*entity.Session, error)
	Delete(token string) error
	DeleteExpired() error
}
