package service

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/auth-system/internal/domain/entity"
	"github.com/auth-system/internal/domain/repository"
	"github.com/auth-system/internal/infrastructure/email"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

type UserService struct {
	userRepo    repository.UserRepository
	otpRepo     repository.OTPRepository
	sessionRepo repository.SessionRepository
	emailSvc    email.EmailService
	jwtSecret   string
}

func NewUserService(userRepo repository.UserRepository, otpRepo repository.OTPRepository,
	sessionRepo repository.SessionRepository, emailSvc email.EmailService, jwtSecret string) *UserService {
	return &UserService{
		userRepo:    userRepo,
		otpRepo:     otpRepo,
		sessionRepo: sessionRepo,
		emailSvc:    emailSvc,
		jwtSecret:   jwtSecret,
	}
}

type RegisterRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=8"`
	FirstName string `json:"first_name" binding:"required"`
	LastName  string `json:"last_name" binding:"required"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	TOTPCode string `json:"totp_code,omitempty"`
}

type AuthResponse struct {
	Token       string       `json:"token"`
	User        *entity.User `json:"user"`
	RequiresMFA bool         `json:"requires_mfa,omitempty"`
	TempToken   string       `json:"temp_token,omitempty"`
}

type MFASetupResponse struct {
	Secret      string   `json:"secret"`
	QRCodeURL   string   `json:"qr_code_url"`
	BackupCodes []string `json:"backup_codes"`
}

func (s *UserService) Register(req RegisterRequest) error {
	// Check if user already exists
	if _, err := s.userRepo.GetByEmail(req.Email); err == nil {
		return errors.New("user already exists")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Create user
	user := &entity.User{
		ID:              uuid.New(),
		Email:           req.Email,
		Password:        string(hashedPassword),
		FirstName:       req.FirstName,
		LastName:        req.LastName,
		IsEmailVerified: false,
		IsMFAEnabled:    false,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if err := s.userRepo.Create(user); err != nil {
		return err
	}

	// Generate and send email verification OTP
	return s.SendEmailVerificationOTP(user.ID)
}

func (s *UserService) Login(req LoginRequest) (*AuthResponse, error) {
	// Get user by email
	user, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("invalid credentials")
		}
		return nil, err
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Check if email is verified
	if !user.IsEmailVerified {
		return nil, errors.New("email not verified")
	}

	// If MFA is enabled, require TOTP code
	if user.IsMFAEnabled {
		if req.TOTPCode == "" {
			// Generate temporary token for MFA verification
			tempToken, err := s.generateTempToken(user.ID)
			if err != nil {
				return nil, err
			}

			return &AuthResponse{
				RequiresMFA: true,
				TempToken:   tempToken,
			}, nil
		}

		// Verify TOTP code
		if !totp.Validate(req.TOTPCode, user.MFASecret) {
			return nil, errors.New("invalid TOTP code")
		}
	}

	// Generate JWT token
	token, err := s.generateJWTToken(user.ID)
	if err != nil {
		return nil, err
	}

	// Create session
	session := &entity.Session{
		ID:        uuid.New(),
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	if err := s.sessionRepo.Create(session); err != nil {
		return nil, err
	}

	return &AuthResponse{
		Token: token,
		User:  user,
	}, nil
}

func (s *UserService) VerifyMFA(tempToken, totpCode string) (*AuthResponse, error) {
	// Verify temp token
	userID, err := s.verifyTempToken(tempToken)
	if err != nil {
		return nil, err
	}

	// Get user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, err
	}

	// Verify TOTP code
	if !totp.Validate(totpCode, user.MFASecret) {
		return nil, errors.New("invalid TOTP code")
	}

	// Generate JWT token
	token, err := s.generateJWTToken(user.ID)
	if err != nil {
		return nil, err
	}

	// Create session
	session := &entity.Session{
		ID:        uuid.New(),
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	if err := s.sessionRepo.Create(session); err != nil {
		return nil, err
	}

	return &AuthResponse{
		Token: token,
		User:  user,
	}, nil
}

func (s *UserService) SendEmailVerificationOTP(userID uuid.UUID) error {
	// Generate OTP
	otp := s.generateOTP(6)

	// Save OTP to database
	otpEntity := &entity.OTP{
		ID:        uuid.New(),
		UserID:    userID,
		Code:      otp,
		Type:      entity.OTPTypeEmailVerification,
		ExpiresAt: time.Now().Add(10 * time.Minute),
		Used:      false,
		CreatedAt: time.Now(),
	}

	if err := s.otpRepo.Create(otpEntity); err != nil {
		return err
	}

	// Get user for email
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return err
	}

	// Send email
	return s.emailSvc.SendOTP(user.Email, otp, "email_verification")
}

func (s *UserService) VerifyEmail(code string) error {
	// Get OTP
	otpEntity, err := s.otpRepo.GetByCode(code, entity.OTPTypeEmailVerification)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.New("invalid or expired OTP")
		}
		return err
	}

	// Mark OTP as used
	otpEntity.Used = true
	if err := s.otpRepo.Update(otpEntity); err != nil {
		return err
	}

	// Update user email verification status
	user, err := s.userRepo.GetByID(otpEntity.UserID)
	if err != nil {
		return err
	}

	user.IsEmailVerified = true
	user.UpdatedAt = time.Now()

	return s.userRepo.Update(user)
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
	if !totp.Validate(totpCode, user.MFASecret) {
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
	if !totp.Validate(totpCode, user.MFASecret) {
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

func (s *UserService) GetUserByID(userID uuid.UUID) (*entity.User, error) {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *UserService) ResendEmailVerification(email string) error {
	// Get user by email
	user, err := s.userRepo.GetByEmail(email)
	if err != nil {
		// Don't reveal if email exists or not for security
		return nil
	}

	// Check if already verified
	if user.IsEmailVerified {
		return nil
	}

	// Send new verification OTP
	return s.SendEmailVerificationOTP(user.ID)
}

func (s *UserService) ForgotPassword(email string) error {
	// Get user by email
	user, err := s.userRepo.GetByEmail(email)
	if err != nil {
		// Don't reveal if email exists or not for security
		return nil
	}

	// Generate password reset OTP
	otp := s.generateOTP(6)

	// Save OTP to database
	otpEntity := &entity.OTP{
		ID:        uuid.New(),
		UserID:    user.ID,
		Code:      otp,
		Type:      entity.OTPTypePasswordReset,
		ExpiresAt: time.Now().Add(10 * time.Minute),
		Used:      false,
		CreatedAt: time.Now(),
	}

	if err := s.otpRepo.Create(otpEntity); err != nil {
		return err
	}

	// Send password reset email
	return s.emailSvc.SendOTP(user.Email, otp, "password_reset")
}

func (s *UserService) ResetPassword(code, newPassword string) error {
	// Get OTP
	otpEntity, err := s.otpRepo.GetByCode(code, entity.OTPTypePasswordReset)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.New("invalid or expired OTP")
		}
		return err
	}

	// Mark OTP as used
	otpEntity.Used = true
	if err := s.otpRepo.Update(otpEntity); err != nil {
		return err
	}

	// Update user password
	user, err := s.userRepo.GetByID(otpEntity.UserID)
	if err != nil {
		return err
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.Password = string(hashedPassword)
	user.UpdatedAt = time.Now()

	return s.userRepo.Update(user)
}

// Private helper methods
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
