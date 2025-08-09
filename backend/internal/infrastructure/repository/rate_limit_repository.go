package repository

import (
	"database/sql"
	"fmt"

	"github.com/auth-system/internal/domain/entity"
	"github.com/auth-system/internal/domain/repository"
)

type rateLimitRepository struct {
	db *sql.DB
}

func NewRateLimitRepository(db *sql.DB) repository.RateLimitRepository {
	return &rateLimitRepository{db: db}
}

func (r *rateLimitRepository) Increment(key string, windowSeconds int) (*entity.RateLimit, error) {
	query := `INSERT INTO rate_limits (key, count, expires_at, created_at)
              VALUES ($1, 1, NOW() + INTERVAL '%d seconds', NOW())
              ON CONFLICT (key) 
              DO UPDATE SET count = rate_limits.count + 1
              WHERE rate_limits.expires_at > NOW()
              RETURNING key, count, expires_at, created_at`

	rl := &entity.RateLimit{}
	err := r.db.QueryRow(fmt.Sprintf(query, windowSeconds), key).Scan(
		&rl.Key, &rl.Count, &rl.ExpiresAt, &rl.CreatedAt)
	if err != nil {
		return nil, err
	}
	return rl, nil
}

func (r *rateLimitRepository) Get(key string) (*entity.RateLimit, error) {
	rl := &entity.RateLimit{}
	query := `SELECT key, count, expires_at, created_at FROM rate_limits 
              WHERE key = $1 AND expires_at > NOW()`

	err := r.db.QueryRow(query, key).Scan(&rl.Key, &rl.Count, &rl.ExpiresAt, &rl.CreatedAt)
	if err != nil {
		return nil, err
	}
	return rl, nil
}

func (r *rateLimitRepository) DeleteExpired() error {
	query := `DELETE FROM rate_limits WHERE expires_at < NOW()`
	_, err := r.db.Exec(query)
	return err
}
