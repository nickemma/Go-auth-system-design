package repository

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/auth-system/internal/domain/entity"
	"github.com/auth-system/internal/domain/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type sessionRepository struct {
	db *sql.DB
}

func NewSessionRepository(db *sql.DB) repository.SessionRepository {
	return &sessionRepository{db: db}
}

func (r *sessionRepository) Create(session *entity.Session) error {
	query := `INSERT INTO sessions (id, user_id, token, expires_at, created_at)
              VALUES ($1, $2, $3, $4, $5)`

	_, err := r.db.Exec(query, session.ID, session.UserID, session.Token, session.ExpiresAt, session.CreatedAt)
	return err
}

func (r *sessionRepository) GetByToken(token string) (*entity.Session, error) {
	session := &entity.Session{}
	query := `SELECT id, user_id, token, expires_at, created_at
              FROM sessions WHERE token = $1 AND expires_at > NOW()`

	err := r.db.QueryRow(query, token).Scan(&session.ID, &session.UserID, &session.Token,
		&session.ExpiresAt, &session.CreatedAt)
	if err != nil {
		return nil, err
	}
	return s.userRepo.Update(user)
}

type MFASetupResponse struct {
	Secret      string   `json:"secret"`
	QRCodeURL   string   `json:"qr_code_url"`
	BackupCodes []string `json:"backup_codes"`
}

func (s *UserService) SetupMFA(userID uuid.UUID) (*MFASetupResponse, error) {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, err
	}

	if user.IsMFAEnabled {
		return nil, errors.New("MFA is already enabled")
	}

	// Generate TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Auth System",
		AccountName: user.Email,
		SecretSize:  32,
	})
	if err != nil {
		return nil, err
	}

	// Generate backup codes
	backupCodes := make([]string, 10)
	for i := range backupCodes {
		backupCodes[i] = s.generateOTP(8)
	}

	// Save secret to user (but don't enable MFA yet)
	user.MFASecret = key.Secret()
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(user); err != nil {
		return nil, err
	}

	// Send backup codes via email
	if err := s.emailSvc.SendMFABackupCodes(user.Email, backupCodes); err != nil {
		return nil, err
	}

	return &MFASetupResponse{
		Secret:      key.Secret(),
		QRCodeURL:   key.URL(),
		BackupCodes: backupCodes,
	}, nil
}

func (s *UserService) EnableMFA(userID uuid.UUID, totpCode string) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return err
	}

	if user.MFASecret == "" {
		return errors.New("MFA setup not initiated")
	}

	// Verify TOTP code
	if !totp.Validate(totpCode, user.MFASecret, time.Now()) {
		return errors.New("invalid TOTP code")
	}

	// Enable MFA
	user.IsMFAEnabled = true
	user.UpdatedAt = time.Now()

	return s.userRepo.Update(user)
}

func (s *UserService) DisableMFA(userID uuid.UUID, totpCode string) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return err
	}

	if !user.IsMFAEnabled {
		return errors.New("MFA is not enabled")
	}

	// Verify TOTP code
	if !totp.Validate(totpCode, user.MFASecret, time.Now()) {
		return errors.New("invalid TOTP code")
	}

	// Disable MFA
	user.IsMFAEnabled = false
	user.MFASecret = ""
	user.UpdatedAt = time.Now()

	return s.userRepo.Update(user)
}

func (s *UserService) Logout(token string) error {
	return s.sessionRepo.Delete(token)
}

func (s *UserService) GetUserByToken(token string) (*entity.User, error) {
	// Verify JWT token
	userID, err := s.verifyJWTToken(token)
	if err != nil {
		return nil, err
	}

	// Check if session exists
	session, err := s.sessionRepo.GetByToken(token)
	if err != nil {
		return nil, errors.New("invalid session")
	}

	if session.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("session expired")
	}

	return s.userRepo.GetByID(userID)
}

func (s *UserService) generateOTP(length int) string {
	const digits = "0123456789"
	result := make([]byte, length)

	for i := range result {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		result[i] = digits[num.Int64()]
	}

	return string(result)
}

func (s *UserService) generateJWTToken(userID uuid.UUID) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID.String(),
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.jwtSecret))
}

func (s *UserService) generateTempToken(userID uuid.UUID) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID.String(),
		"exp":     time.Now().Add(5 * time.Minute).Unix(),
		"iat":     time.Now().Unix(),
		"temp":    true,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.jwtSecret))
}

func (s *UserService) verifyJWTToken(tokenString string) (uuid.UUID, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		return uuid.Nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if temp, exists := claims["temp"]; exists && temp.(bool) {
			return uuid.Nil, errors.New("temporary token not allowed")
		}

		userIDStr, ok := claims["user_id"].(string)
		if !ok {
			return uuid.Nil, errors.New("invalid token claims")
		}

		return uuid.Parse(userIDStr)
	}

	return uuid.Nil, errors.New("invalid token")
}

func (s *UserService) verifyTempToken(tokenString string) (uuid.UUID, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		return uuid.Nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		temp, exists := claims["temp"]
		if !exists || !temp.(bool) {
			return uuid.Nil, errors.New("not a temporary token")
		}

		userIDStr, ok := claims["user_id"].(string)
		if !ok {
			return uuid.Nil, errors.New("invalid token claims")
		}

		return uuid.Parse(userIDStr)
	}

	return uuid.Nil, errors.New("invalid token")
}

func (r *sessionRepository) GetByUserID(userID uuid.UUID) ([]*entity.Session, error) {
	query := `SELECT id, user_id, token, expires_at, created_at
              FROM sessions WHERE user_id = $1 AND expires_at > NOW()`

	rows, err := r.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*entity.Session
	for rows.Next() {
		session := &entity.Session{}
		err := rows.Scan(&session.ID, &session.UserID, &session.Token, &session.ExpiresAt, &session.CreatedAt)
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
