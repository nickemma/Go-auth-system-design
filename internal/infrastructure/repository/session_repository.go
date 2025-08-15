package repository

import (
	"database/sql"

	"github.com/auth-system/internal/domain/entity"
	"github.com/auth-system/internal/domain/repository"
	"github.com/google/uuid"
)

type sessionRepository struct {
	db *sql.DB
}

func NewSessionRepository(db *sql.DB) repository.SessionRepository {
	return &sessionRepository{db: db}
}

func (r *sessionRepository) Create(session *entity.Session) error {
	query := `INSERT INTO sessions (id, user_id, token, expires_at, ip_address, user_agent, created_at)
              VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.db.Exec(query, session.ID, session.UserID, session.Token,
		session.ExpiresAt, session.IPAddress, session.UserAgent, session.CreatedAt)
	return err
}

func (r *sessionRepository) GetByToken(token string) (*entity.Session, error) {
	session := &entity.Session{}
	query := `SELECT id, user_id, token, expires_at, ip_address, user_agent, created_at
              FROM sessions WHERE token = $1 AND expires_at > NOW()`

	err := r.db.QueryRow(query, token).Scan(&session.ID, &session.UserID, &session.Token,
		&session.ExpiresAt, &session.IPAddress, &session.UserAgent, &session.CreatedAt)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (r *sessionRepository) GetByUserID(userID uuid.UUID) ([]*entity.Session, error) {
	query := `SELECT id, user_id, token, expires_at, ip_address, user_agent, created_at
              FROM sessions WHERE user_id = $1 AND expires_at > NOW()`

	rows, err := r.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*entity.Session
	for rows.Next() {
		session := &entity.Session{}
		err := rows.Scan(&session.ID, &session.UserID, &session.Token,
			&session.ExpiresAt, &session.IPAddress, &session.UserAgent, &session.CreatedAt)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

func (r *sessionRepository) Delete(token string) error {
	query := `DELETE FROM sessions WHERE token = $1`
	_, err := r.db.Exec(query, token)
	return err
}

func (r *sessionRepository) DeleteExpired() error {
	query := `DELETE FROM sessions WHERE expires_at < NOW()`
	_, err := r.db.Exec(query)
	return err
}
