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
	// Single query approach: Reset if expired, otherwise increment
	query := `INSERT INTO rate_limits (key, count, expires_at, created_at)
              VALUES ($1, 1, NOW() + INTERVAL '%d seconds', NOW())
              ON CONFLICT (key) 
              DO UPDATE SET 
                count = CASE 
                  WHEN rate_limits.expires_at <= NOW() THEN 1 
                  ELSE rate_limits.count + 1 
                END,
                expires_at = CASE 
                  WHEN rate_limits.expires_at <= NOW() THEN NOW() + INTERVAL '%d seconds'
                  ELSE rate_limits.expires_at 
                END,
                created_at = CASE 
                  WHEN rate_limits.expires_at <= NOW() THEN NOW()
                  ELSE rate_limits.created_at 
                END
              RETURNING key, count, expires_at, created_at`

	rl := &entity.RateLimit{}
	err := r.db.QueryRow(fmt.Sprintf(query, windowSeconds, windowSeconds), key).Scan(
		&rl.Key, &rl.Count, &rl.ExpiresAt, &rl.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to increment rate limit: %v", err)
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
