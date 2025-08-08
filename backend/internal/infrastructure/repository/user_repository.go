package repository

import (
	"database/sql"

	"github.com/auth-system/internal/domain/entity"
	"github.com/auth-system/internal/domain/repository"
	"github.com/google/uuid"
)

type userRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) repository.UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(user *entity.User) error {
	query := `INSERT INTO users (id, email, password, first_name, last_name, is_email_verified, is_mfa_enabled, mfa_secret, created_at, updated_at)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := r.db.Exec(query, user.ID, user.Email, user.Password, user.FirstName, user.LastName,
		user.IsEmailVerified, user.IsMFAEnabled, user.MFASecret, user.CreatedAt, user.UpdatedAt)
	return err
}

func (r *userRepository) GetByID(id uuid.UUID) (*entity.User, error) {
	user := &entity.User{}
	query := `SELECT id, email, password, first_name, last_name, is_email_verified, is_mfa_enabled, mfa_secret, created_at, updated_at
              FROM users WHERE id = $1`

	err := r.db.QueryRow(query, id).Scan(&user.ID, &user.Email, &user.Password, &user.FirstName, &user.LastName,
		&user.IsEmailVerified, &user.IsMFAEnabled, &user.MFASecret, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *userRepository) GetByEmail(email string) (*entity.User, error) {
	user := &entity.User{}
	query := `SELECT id, email, password, first_name, last_name, is_email_verified, is_mfa_enabled, mfa_secret, created_at, updated_at
              FROM users WHERE email = $1`

	err := r.db.QueryRow(query, email).Scan(&user.ID, &user.Email, &user.Password, &user.FirstName, &user.LastName,
		&user.IsEmailVerified, &user.IsMFAEnabled, &user.MFASecret, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *userRepository) Update(user *entity.User) error {
	query := `UPDATE users SET email = $2, password = $3, first_name = $4, last_name = $5, 
              is_email_verified = $6, is_mfa_enabled = $7, mfa_secret = $8, updated_at = $9
              WHERE id = $1`

	_, err := r.db.Exec(query, user.ID, user.Email, user.Password, user.FirstName, user.LastName,
		user.IsEmailVerified, user.IsMFAEnabled, user.MFASecret, user.UpdatedAt)
	return err
}

func (r *userRepository) Delete(id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := r.db.Exec(query, id)
	return err
}
