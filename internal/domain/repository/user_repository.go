package repository

import (
	"github.com/auth-system/internal/domain/entity"
	"github.com/google/uuid"
)

type UserRepository interface {
	Create(user *entity.User) error
	GetByID(id uuid.UUID) (*entity.User, error)
	GetByEmail(email string) (*entity.User, error)
	Update(user *entity.User) error
	Delete(id uuid.UUID) error
}
