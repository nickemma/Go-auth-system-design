package repository

import (
	"github.com/auth-system/internal/domain/entity"
	"github.com/google/uuid"

	"time"
)

type UserRepository interface {
	Create(user *entity.User) error
	GetByID(id uuid.UUID) (*entity.User, error)
	UpdateUserRole(id uuid.UUID, role string) error
	GetAll() ([]*entity.User, error)
	GetByEmail(email string) (*entity.User, error)
	Update(user *entity.User) error
	Delete(id uuid.UUID) error

	IncrementLoginAttempts(email string) error
	LockAccount(email string, until time.Time) error
	ResetLoginAttempts(email string) error
}
