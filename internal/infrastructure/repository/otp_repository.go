package repository

import (
	"database/sql"

	"github.com/auth-system/internal/domain/entity"
	"github.com/auth-system/internal/domain/repository"
	"github.com/google/uuid"
)

type otpRepository struct {
	db *sql.DB
}

func NewOTPRepository(db *sql.DB) repository.OTPRepository {
	return &otpRepository{db: db}
}

func (r *otpRepository) Create(otp *entity.OTP) error {
	query := `INSERT INTO otps (id, user_id, code, type, expires_at, used, created_at)
              VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.db.Exec(query, otp.ID, otp.UserID, otp.Code, otp.Type, otp.ExpiresAt, otp.Used, otp.CreatedAt)
	return err
}

func (r *otpRepository) GetByCode(code string, otpType entity.OTPType) (*entity.OTP, error) {
	otp := &entity.OTP{}
	query := `SELECT id, user_id, code, type, expires_at, used, created_at
              FROM otps WHERE code = $1 AND type = $2 AND expires_at > NOW() AND used = FALSE`

	err := r.db.QueryRow(query, code, otpType).Scan(&otp.ID, &otp.UserID, &otp.Code, &otp.Type,
		&otp.ExpiresAt, &otp.Used, &otp.CreatedAt)
	if err != nil {
		return nil, err
	}
	return otp, nil
}

func (r *otpRepository) GetByUserID(userID uuid.UUID, otpType entity.OTPType) (*entity.OTP, error) {
	otp := &entity.OTP{}
	query := `SELECT id, user_id, code, type, expires_at, used, created_at
              FROM otps WHERE user_id = $1 AND type = $2 AND expires_at > NOW() AND used = FALSE
              ORDER BY created_at DESC LIMIT 1`

	err := r.db.QueryRow(query, userID, otpType).Scan(&otp.ID, &otp.UserID, &otp.Code, &otp.Type,
		&otp.ExpiresAt, &otp.Used, &otp.CreatedAt)
	if err != nil {
		return nil, err
	}
	return otp, nil
}

func (r *otpRepository) Update(otp *entity.OTP) error {
	query := `UPDATE otps SET used = $2 WHERE id = $1`
	_, err := r.db.Exec(query, otp.ID, otp.Used)
	return err
}

func (r *otpRepository) DeleteExpired() error {
	query := `DELETE FROM otps WHERE expires_at < NOW()`
	_, err := r.db.Exec(query)
	return err
}
