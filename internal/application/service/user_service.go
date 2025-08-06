package service

import (
	"database/sql"
	"errors"
	"time"

	"github.com/auth-system/internal/domain/entity"
	"github.com/auth-system/internal/domain/repository"
	"github.com/auth-system/internal/infrastructure/email"
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
		if !totp.Validate(req.TOTPCode, user.MFASecret, time.Now()) {
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
	if !totp.Validate(totpCode, user.MFASecret, time.Now()) {
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

func (s *UserService) generateJWTToken(userID uuid.UUID) (string, error) {
	// Implementation for generating JWT token

	// This is a placeholder; actual implementation will depend on your JWT library
	return "generated_jwt_token", nil
}

func (s *UserService) SetupMFA(userID uuid.UUID) (any, error) {
	// Generate TOTP secret
	mfaSecret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "AuthSystem",
		AccountName: userID.String(),
	})
	if err != nil {
		return nil, err
	}

	// Save MFA secret to user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, err
	}

	user.MFASecret = mfaSecret.Secret()
	user.IsMFAEnabled = true
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(user); err != nil {
		return nil, err
	}

	return mfaSecret.URL(), nil
}

func (s *UserService) EnableMFA(userID uuid.UUID, totpCode string) error {
	// Get user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return err
	}
	if user.IsMFAEnabled {
		return errors.New("MFA is already enabled")
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
	// Get user
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

func (s *UserService) generateTempToken(userID uuid.UUID) (string, error) {
	// Generate a temporary token for MFA verification
	tempToken := uuid.New().String()

	// Save the temporary token to the session repository
	session := &entity.Session{
		ID:        uuid.New(),
		UserID:    userID,
		Token:     tempToken,
		ExpiresAt: time.Now().Add(15 * time.Minute), // Token valid for 15 minutes
		CreatedAt: time.Now(),
	}

	if err := s.sessionRepo.Create(session); err != nil {
		return "", err
	}

	return tempToken, nil
}

func (s *UserService) verifyTempToken(tempToken string) (uuid.UUID, error) {
	// Verify the temporary token
	session, err := s.sessionRepo.GetByToken(tempToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return uuid.Nil, errors.New("invalid or expired temporary token")
		}
		return uuid.Nil, err
	}

	// Check if the session is still valid
	if session.ExpiresAt.Before(time.Now()) {
		return uuid.Nil, errors.New("temporary token has expired")
	}

	return session.UserID, nil
}

func (s *UserService) generateOTP(length int) string {
	// Generate a random OTP of specified length
	otp := make([]byte, length)
	for i := range otp {
		otp[i] = '0' + byte(i%10) // Simple numeric OTP for demonstration
	}
	return string(otp)
}

func (s *UserService) GetUserByID(userID uuid.UUID) (*entity.User, error) {
	// Get user by ID
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, err
	}
	return user, nil
}
