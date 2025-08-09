package repository

import (
	"github.com/auth-system/internal/domain/entity"
)

type RateLimitRepository interface {
	Increment(key string, windowSeconds int) (*entity.RateLimit, error)
	Get(key string) (*entity.RateLimit, error)
	DeleteExpired() error
}
