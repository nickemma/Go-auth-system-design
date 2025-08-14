package repository

import (
	"database/sql"
	"encoding/json"
	"time"

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
	backupCodesJSON, _ := json.Marshal(user.BackupCodes)

	query := `INSERT INTO users (id, email, password, first_name, last_name, phone_number, 
              is_email_verified, is_phone_verified, is_mfa_enabled, mfa_secret, preferred_mfa, 
              backup_codes, login_attempts, locked_until, created_at, updated_at)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`

	_, err := r.db.Exec(query, user.ID, user.Email, user.Password, user.FirstName, user.LastName,
		user.PhoneNumber, user.IsEmailVerified, user.IsPhoneVerified, user.IsMFAEnabled,
		user.MFASecret, user.PreferredMFA, backupCodesJSON, user.LoginAttempts, user.LockedUntil,
		user.CreatedAt, user.UpdatedAt)
	return err
}

func (r *userRepository) GetByID(id uuid.UUID) (*entity.User, error) {
	user := &entity.User{}
	var backupCodesJSON []byte

	query := `SELECT id, email, password, first_name, last_name, phone_number, 
              is_email_verified, is_phone_verified, is_mfa_enabled, mfa_secret, preferred_mfa, 
              backup_codes, login_attempts, locked_until, created_at, updated_at
              FROM users WHERE id = $1`

	err := r.db.QueryRow(query, id).Scan(&user.ID, &user.Email, &user.Password, &user.FirstName,
		&user.LastName, &user.PhoneNumber, &user.IsEmailVerified, &user.IsPhoneVerified,
		&user.IsMFAEnabled, &user.MFASecret, &user.PreferredMFA, &backupCodesJSON,
		&user.LoginAttempts, &user.LockedUntil, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		return nil, err
	}

	if backupCodesJSON != nil {
		json.Unmarshal(backupCodesJSON, &user.BackupCodes)
	}

	return user, nil
}

func (r *userRepository) GetByEmail(email string) (*entity.User, error) {
	user := &entity.User{}
	var backupCodesJSON []byte

	query := `SELECT id, email, password, first_name, last_name, phone_number, 
              is_email_verified, is_phone_verified, is_mfa_enabled, mfa_secret, preferred_mfa, 
              backup_codes, login_attempts, locked_until, created_at, updated_at
              FROM users WHERE email = $1`

	err := r.db.QueryRow(query, email).Scan(&user.ID, &user.Email, &user.Password, &user.FirstName,
		&user.LastName, &user.PhoneNumber, &user.IsEmailVerified, &user.IsPhoneVerified,
		&user.IsMFAEnabled, &user.MFASecret, &user.PreferredMFA, &backupCodesJSON,
		&user.LoginAttempts, &user.LockedUntil, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		return nil, err
	}

	if backupCodesJSON != nil {
		json.Unmarshal(backupCodesJSON, &user.BackupCodes)
	}

	return user, nil
}

func (r *userRepository) Update(user *entity.User) error {
	backupCodesJSON, _ := json.Marshal(user.BackupCodes)

	query := `UPDATE users SET email = $2, password = $3, first_name = $4, last_name = $5, 
              phone_number = $6, is_email_verified = $7, is_phone_verified = $8, is_mfa_enabled = $9, 
              mfa_secret = $10, preferred_mfa = $11, backup_codes = $12, login_attempts = $13, 
              locked_until = $14, updated_at = $15 WHERE id = $1`

	_, err := r.db.Exec(query, user.ID, user.Email, user.Password, user.FirstName, user.LastName,
		user.PhoneNumber, user.IsEmailVerified, user.IsPhoneVerified, user.IsMFAEnabled,
		user.MFASecret, user.PreferredMFA, backupCodesJSON, user.LoginAttempts, user.LockedUntil,
		user.UpdatedAt)
	return err
}

func (r *userRepository) Delete(id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := r.db.Exec(query, id)
	return err
}

func (r *userRepository) IncrementLoginAttempts(email string) error {
	query := `UPDATE users SET login_attempts = login_attempts + 1 WHERE email = $1`
	_, err := r.db.Exec(query, email)
	return err
}

func (r *userRepository) LockAccount(email string, until time.Time) error {
	query := `UPDATE users SET locked_until = $2 WHERE email = $1`
	_, err := r.db.Exec(query, email, until)
	return err
}

func (r *userRepository) ResetLoginAttempts(email string) error {
	query := `UPDATE users SET login_attempts = 0, locked_until = NULL WHERE email = $1`
	_, err := r.db.Exec(query, email)
	return err
}
