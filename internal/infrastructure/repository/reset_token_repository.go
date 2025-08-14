package repository

import (
	"database/sql"

	"github.com/auth-system/internal/domain/entity"
	"github.com/auth-system/internal/domain/repository"
	"github.com/google/uuid"
)

type resetTokenRepository struct {
	db *sql.DB
}

func NewResetTokenRepository(db *sql.DB) repository.ResetTokenRepository {
	return &resetTokenRepository{db: db}
}

func (r *resetTokenRepository) Create(token *entity.ResetToken) error {
	query := `INSERT INTO reset_tokens (id, user_id, token, expires_at, used, ip_address, created_at)
              VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.db.Exec(query, token.ID, token.UserID, token.Token, token.ExpiresAt,
		token.Used, token.IPAddress, token.CreatedAt)
	return err
}

func (r *resetTokenRepository) GetByToken(token string) (*entity.ResetToken, error) {
	resetToken := &entity.ResetToken{}
	query := `SELECT id, user_id, token, expires_at, used, ip_address, created_at
              FROM reset_tokens WHERE token = $1 AND expires_at > NOW() AND used = FALSE`

	err := r.db.QueryRow(query, token).Scan(&resetToken.ID, &resetToken.UserID,
		&resetToken.Token, &resetToken.ExpiresAt, &resetToken.Used, &resetToken.IPAddress,
		&resetToken.CreatedAt)
	if err != nil {
		return nil, err
	}
	return resetToken, nil
}

func (r *resetTokenRepository) MarkAsUsed(id uuid.UUID) error {
	query := `UPDATE reset_tokens SET used = TRUE WHERE id = $1`
	_, err := r.db.Exec(query, id)
	return err
}

func (r *resetTokenRepository) DeleteExpired() error {
	query := `DELETE FROM reset_tokens WHERE expires_at < NOW()`
	_, err := r.db.Exec(query)
	return err
}
