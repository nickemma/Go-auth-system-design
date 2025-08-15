package service

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/auth-system/internal/domain/entity"
	"github.com/auth-system/internal/domain/repository"
	"github.com/auth-system/internal/infrastructure/cache"
	"github.com/auth-system/internal/infrastructure/email"
	"github.com/auth-system/internal/infrastructure/sms"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

type UserService struct {
	userRepo       repository.UserRepository
	otpRepo        repository.OTPRepository
	sessionRepo    repository.SessionRepository
	resetTokenRepo repository.ResetTokenRepository
	rateLimitRepo  repository.RateLimitRepository
	emailSvc       email.EmailService
	smsSvc         sms.SMSService
	cache          *cache.RedisCache
	jwtSecret      string
	baseURL        string
}

func NewUserService(
	userRepo repository.UserRepository,
	otpRepo repository.OTPRepository,
	sessionRepo repository.SessionRepository,
	resetTokenRepo repository.ResetTokenRepository,
	rateLimitRepo repository.RateLimitRepository,
	emailSvc email.EmailService,
	smsSvc sms.SMSService,
	cache *cache.RedisCache,
	jwtSecret string,
	baseURL string,
) *UserService {
	return &UserService{
		userRepo:       userRepo,
		otpRepo:        otpRepo,
		sessionRepo:    sessionRepo,
		emailSvc:       emailSvc,
		resetTokenRepo: resetTokenRepo,
		rateLimitRepo:  rateLimitRepo,
		smsSvc:         smsSvc,
		cache:          cache,
		jwtSecret:      jwtSecret,
		baseURL:        baseURL,
	}
}

type RegisterRequest struct {
	Email       string  `json:"email" binding:"required,email"`
	Password    string  `json:"password" binding:"required,min=8"`
	FirstName   string  `json:"first_name" binding:"required"`
	LastName    string  `json:"last_name" binding:"required"`
	PhoneNumber *string `json:"phone_number,omitempty"`
	Role        string  `json:"role,omitempty"` // Optional, defaults to "user"
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Success     bool         `json:"success"`
	RequiresMFA bool         `json:"requires_mfa,omitempty"`
	TempToken   string       `json:"temp_token,omitempty"`
	MFAMethods  []string     `json:"mfa_methods,omitempty"`
	Token       string       `json:"token,omitempty"`
	User        *entity.User `json:"user,omitempty"`
}

type MFASetupResponse struct {
	Secret      string   `json:"secret"`
	QRCodeURL   string   `json:"qr_code_url"`
	BackupCodes []string `json:"backup_codes"`
}

type SendMFACodeRequest struct {
	TempToken string `json:"temp_token" binding:"required"`
	Method    string `json:"method" binding:"required"` // "sms"
}

type VerifyMFARequest struct {
	TempToken string `json:"temp_token" binding:"required"`
	Code      string `json:"code" binding:"required"`
	Method    string `json:"method" binding:"required"` // "authenticator", "sms", "backup_code"
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=8"`
}

// Registration
func (s *UserService) Register(req RegisterRequest, ipAddress string) error {

	// Check if user already exists
	if _, err := s.userRepo.GetByEmail(req.Email); err == nil {
		return errors.New("user already exists")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Set default role if not provided
	role := req.Role
	if role == "" {
		role = "user"
	}

	// Validate role
	if role != "user" && role != "admin" {
		return errors.New("invalid role")
	}

	// Create user
	user := &entity.User{
		ID:              uuid.New(),
		Email:           req.Email,
		Password:        string(hashedPassword),
		FirstName:       req.FirstName,
		LastName:        req.LastName,
		PhoneNumber:     req.PhoneNumber,
		Role:            role,
		IsEmailVerified: false,
		IsPhoneVerified: false,
		IsMFAEnabled:    false,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if err := s.userRepo.Create(user); err != nil {
		return err
	}

	// Generate and send email verification OTP
	return s.SendEmailVerificationOTP(user.ID, ipAddress)
}

// Login (Step 1)
func (s *UserService) Login(req LoginRequest, ipAddress, userAgent string) (*LoginResponse, error) {
	// Rate limiting
	if err := s.checkRateLimit("login:"+ipAddress, 10, 300); err != nil {
		return nil, err
	}

	// Get user
	user, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		s.handleFailedLogin(req.Email)
		return nil, errors.New("invalid credentials")
	}

	// Check account lock
	if err := s.checkAccountLock(user); err != nil {
		return nil, err
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		s.handleFailedLogin(req.Email)
		return nil, errors.New("invalid credentials")
	}

	// Reset login attempts on successful password verification
	s.userRepo.ResetLoginAttempts(req.Email)

	// Check email verification
	if !user.IsEmailVerified {
		return nil, errors.New("email not verified")
	}

	// If MFA is enabled, return temp token
	if user.IsMFAEnabled {
		tempToken, err := s.generateTempToken(user.ID)
		if err != nil {
			return nil, err
		}

		// Determine available MFA methods
		methods := []string{"authenticator"}

		// Add SMS only if phone is verified AND SMS service is enabled
		if user.PhoneNumber != nil && *user.PhoneNumber != "" &&
			user.IsPhoneVerified && s.smsSvc.IsEnabled() {
			methods = append(methods, "sms")
		}

		if len(user.BackupCodes) > 0 {
			methods = append(methods, "backup_code")
		}

		return &LoginResponse{
			Success:     true,
			RequiresMFA: true,
			TempToken:   tempToken,
			MFAMethods:  methods,
		}, nil
	}

	// Generate session token and create session
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
		IPAddress: ipAddress,
		UserAgent: userAgent,
		CreatedAt: time.Now(),
	}

	if err := s.sessionRepo.Create(session); err != nil {
		return nil, err
	}

	return &LoginResponse{
		Success: true,
		Token:   token,
		User:    user,
	}, nil
}

// Send MFA Code (Step 2A - for SMS)
func (s *UserService) SendMFACode(req SendMFACodeRequest, ipAddress string) error {
	// Rate limiting
	if err := s.checkRateLimit("mfa_sms:"+ipAddress, 3, 300); err != nil {
		return err
	}

	// Verify temp token
	userID, err := s.verifyTempToken(req.TempToken)
	if err != nil {
		return err
	}

	// Get user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return err
	}

	if req.Method == "sms" {
		// Check if SMS service is enabled
		if !s.smsSvc.IsEnabled() {
			return errors.New("SMS service is not configured")
		}
		// Check if phone number is set and verified
		if user.PhoneNumber == nil || *user.PhoneNumber == "" {
			return errors.New("phone number not configured")
		}

		if !user.IsPhoneVerified {
			return errors.New("phone number not verified")
		}

		// Generate and send SMS OTP
		otp := s.generateOTP(6)

		otpEntity := &entity.OTP{
			ID:        uuid.New(),
			UserID:    userID,
			Code:      otp,
			Type:      entity.OTPTypeMFASMS,
			ExpiresAt: time.Now().Add(5 * time.Minute),
			Used:      false,
			IPAddress: ipAddress,
			CreatedAt: time.Now(),
		}
		if err := s.otpRepo.Create(otpEntity); err != nil {
			return err
		}

		return s.smsSvc.SendOTP(*user.PhoneNumber, otp)
	}

	return errors.New("invalid MFA method")
}

// Verify MFA (Step 2B)
func (s *UserService) VerifyMFA(req VerifyMFARequest, ipAddress, userAgent string) (*LoginResponse, error) {
	// Rate limiting
	if err := s.checkRateLimit("verify_mfa:"+ipAddress, 5, 300); err != nil {
		return nil, err
	}
	// Verify temp token
	userID, err := s.verifyTempToken(req.TempToken)
	if err != nil {
		return nil, err
	}

	// Get user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, err
	}

	// Verify code based on method
	switch req.Method {
	case "authenticator":
		if !totp.Validate(req.Code, user.MFASecret) {
			return nil, errors.New("invalid TOTP code")
		}

	case "sms":
		otpEntity, err := s.otpRepo.GetByUserID(userID, entity.OTPTypeMFASMS)
		if err != nil {
			return nil, errors.New("invalid or expired SMS code")
		}

		if otpEntity.Code != req.Code {
			return nil, errors.New("invalid SMS code")
		}
		// Mark OTP as used
		otpEntity.Used = true
		if err := s.otpRepo.Update(otpEntity); err != nil {
			return nil, err
		}

	case "backup_code":
		// Check if code exists in backup codes
		found := false
		remainingCodes := []string{}

		for _, code := range user.BackupCodes {
			if code == req.Code && !found {
				found = true // Remove this code
			} else {
				remainingCodes = append(remainingCodes, code)
			}
		}
		if !found {
			return nil, errors.New("invalid backup code")
		}

		// Update user with remaining backup codes
		user.BackupCodes = remainingCodes
		user.UpdatedAt = time.Now()
		if err := s.userRepo.Update(user); err != nil {
			return nil, err
		}

	default:
		return nil, errors.New("invalid MFA method")
	}
	// Generate session token
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
		IPAddress: ipAddress,
		UserAgent: userAgent,
		CreatedAt: time.Now(),
	}
	if err := s.sessionRepo.Create(session); err != nil {
		return nil, err
	}

	return &LoginResponse{
		Success: true,
		Token:   token,
		User:    user,
	}, nil
}

// Rate limiting
func (s *UserService) checkRateLimit(key string, limit int, windowSeconds int) error {
	rl, err := s.rateLimitRepo.Get(key)
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	if rl != nil && rl.Count >= limit {
		return fmt.Errorf("rate limit exceeded, try again in %d seconds",
			int(rl.ExpiresAt.Sub(time.Now()).Seconds()))
	}

	_, err = s.rateLimitRepo.Increment(key, windowSeconds)
	return err
}

// Email Verification
func (s *UserService) SendEmailVerificationOTP(userID uuid.UUID, ipAddress string) error {
	// Rate limiting
	if err := s.checkRateLimit("email_verify:"+ipAddress, 3, 300); err != nil {
		return err
	}

	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return err
	}

	if user.IsEmailVerified {
		return errors.New("email already verified")
	}
	// Generate OTP
	otp := s.generateOTP(6)

	otpEntity := &entity.OTP{
		ID:        uuid.New(),
		UserID:    userID,
		Code:      otp,
		Type:      entity.OTPTypeEmailVerification,
		ExpiresAt: time.Now().Add(10 * time.Minute),
		Used:      false,
		IPAddress: ipAddress,
		CreatedAt: time.Now(),
	}

	if err := s.otpRepo.Create(otpEntity); err != nil {
		return err
	}

	return s.emailSvc.SendOTP(user.Email, otp, "email_verification")
}

// Account locking
func (s *UserService) checkAccountLock(user *entity.User) error {
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		remaining := int(user.LockedUntil.Sub(time.Now()).Minutes())
		return fmt.Errorf("account locked for %d more minutes due to failed login attempts", remaining)
	}
	return nil
}

func (s *UserService) handleFailedLogin(email string) error {
	user, err := s.userRepo.GetByEmail(email)
	if err != nil {
		return nil // Don't reveal if user exists
	}

	if err := s.userRepo.IncrementLoginAttempts(email); err != nil {
		return err
	}

	// Lock account after 5 failed attempts for 30 minutes
	if user.LoginAttempts+1 >= 5 {
		lockUntil := time.Now().Add(30 * time.Minute)
		return s.userRepo.LockAccount(email, lockUntil)
	}

	return nil
}

func (s *UserService) VerifyEmail(code, ipAddress string) error {
	// Rate limiting
	if err := s.checkRateLimit("verify_email:"+ipAddress, 10, 300); err != nil {
		return err
	}

	otpEntity, err := s.otpRepo.GetByCode(code, entity.OTPTypeEmailVerification)
	if err != nil {
		return errors.New("invalid or expired OTP")
	}

	// Mark OTP as used
	otpEntity.Used = true
	if err := s.otpRepo.Update(otpEntity); err != nil {
		return err
	}

	// Update user
	user, err := s.userRepo.GetByID(otpEntity.UserID)
	if err != nil {
		return err
	}

	user.IsEmailVerified = true
	user.UpdatedAt = time.Now()

	return s.userRepo.Update(user)
}

// MFA Setup
func (s *UserService) SetupMFA(userID uuid.UUID, method string) (*MFASetupResponse, error) {
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

	// Save to user (but don't enable MFA yet)
	user.MFASecret = key.Secret()
	user.BackupCodes = backupCodes
	user.PreferredMFA = method
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

	// Verify TOTP code or backup code
	validCode := totp.Validate(totpCode, user.MFASecret)
	if !validCode {
		// Check if it's a backup code
		for _, code := range user.BackupCodes {
			if code == totpCode {
				validCode = true
				break
			}
		}
	}

	if !validCode {
		return errors.New("invalid code")
	}

	// Disable MFA
	user.IsMFAEnabled = false
	user.MFASecret = ""
	user.BackupCodes = []string{}
	user.PreferredMFA = ""
	user.UpdatedAt = time.Now()

	return s.userRepo.Update(user)
}

func (s *UserService) GetUserByToken(token string) (*entity.User, error) {
	// First verify the JWT token
	userID, err := s.verifyJWTToken(token)
	if err != nil {
		return nil, err
	}

	// Check if this is a temporary token by parsing it
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		// If this is a temporary token, don't check for session
		if temp, exists := claims["temp"]; exists && temp.(bool) {
			return s.userRepo.GetByID(userID)
		}
	}
	// For regular tokens, check session exists
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
	return s.userRepo.GetByID(userID)
}

func (s *UserService) GetAllUsers() ([]*entity.User, error) {
	return s.userRepo.GetAll()
}

func (s *UserService) UpdateUserRole(userID uuid.UUID, newRole string) error {
	// Validate role
	if newRole != "user" && newRole != "admin" {
		return errors.New("invalid role")
	}

	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return err
	}

	user.Role = newRole
	user.UpdatedAt = time.Now()

	return s.userRepo.Update(user)
}

// email Verification
func (s *UserService) ResendEmailVerification(email, ipAddress string) error {
	user, err := s.userRepo.GetByEmail(email)
	if err != nil {
		return nil // Don't reveal if email exists
	}

	if user.IsEmailVerified {
		return nil
	}

	return s.SendEmailVerificationOTP(user.ID, ipAddress)
}

// Phone Verification
func (s *UserService) SendPhoneVerificationOTP(userID uuid.UUID, ipAddress string) error {
	// Rate limiting
	if err := s.checkRateLimit("phone_verify:"+ipAddress, 3, 300); err != nil {
		return err
	}

	// Check if SMS service is enabled
	if !s.smsSvc.IsEnabled() {
		return errors.New("SMS service is not configured")
	}

	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return err
	}

	if user.PhoneNumber == nil || *user.PhoneNumber == "" {
		return errors.New("phone number not set")
	}

	if user.IsPhoneVerified {
		return errors.New("phone already verified")
	}

	// Generate OTP
	otp := s.generateOTP(6)

	otpEntity := &entity.OTP{
		ID:        uuid.New(),
		UserID:    userID,
		Code:      otp,
		Type:      entity.OTPTypePhoneVerification,
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Used:      false,
		IPAddress: ipAddress,
		CreatedAt: time.Now(),
	}

	if err := s.otpRepo.Create(otpEntity); err != nil {
		return err
	}

	return s.smsSvc.SendOTP(*user.PhoneNumber, otp)
}

func (s *UserService) VerifyPhone(code, ipAddress string, userID uuid.UUID) error {
	// Rate limiting
	if err := s.checkRateLimit("verify_phone:"+ipAddress, 10, 300); err != nil {
		return err
	}

	otpEntity, err := s.otpRepo.GetByUserID(userID, entity.OTPTypePhoneVerification)
	if err != nil {
		return errors.New("invalid or expired OTP")
	}

	if otpEntity.Code != code {
		return errors.New("invalid OTP code")
	}

	// Mark OTP as used
	otpEntity.Used = true
	if err := s.otpRepo.Update(otpEntity); err != nil {
		return err
	}

	// Update user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return err
	}

	user.IsPhoneVerified = true
	user.UpdatedAt = time.Now()

	return s.userRepo.Update(user)
}

// Password Reset (Forgot Password)
func (s *UserService) ForgotPassword(email, ipAddress string) error {
	// Rate limiting
	if err := s.checkRateLimit("forgot_password:"+ipAddress, 3, 900); err != nil {
		return err
	}

	user, err := s.userRepo.GetByEmail(email)
	if err != nil {
		return nil // Don't reveal if email exists
	}

	// Generate secure reset token
	token := s.generateSecureToken()

	resetToken := &entity.ResetToken{
		ID:        uuid.New(),
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(1 * time.Hour), // 1 hour expiry
		Used:      false,
		IPAddress: ipAddress,
		CreatedAt: time.Now(),
	}

	if err := s.resetTokenRepo.Create(resetToken); err != nil {
		return err
	}

	// Send reset email with link
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.baseURL, token)
	return s.emailSvc.SendPasswordResetLink(user.Email, resetURL)
}

func (s *UserService) ResetPasswordWithToken(token, newPassword, ipAddress string) error {
	// Rate limiting
	if err := s.checkRateLimit("reset_password:"+ipAddress, 5, 300); err != nil {
		return err
	}

	// Get reset token
	resetToken, err := s.resetTokenRepo.GetByToken(token)
	if err != nil {
		return errors.New("invalid or expired reset token")
	}

	// Mark token as used
	if err := s.resetTokenRepo.MarkAsUsed(resetToken.ID); err != nil {
		return err
	}

	// Update user password
	user, err := s.userRepo.GetByID(resetToken.UserID)
	if err != nil {
		return err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.Password = string(hashedPassword)
	user.UpdatedAt = time.Now()

	// Reset login attempts and unlock account
	user.LoginAttempts = 0
	user.LockedUntil = nil

	return s.userRepo.Update(user)
}

// Password Change (for logged-in users)
func (s *UserService) ChangePassword(userID uuid.UUID, req ChangePasswordRequest) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return err
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.CurrentPassword)); err != nil {
		return errors.New("current password is incorrect")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.Password = string(hashedPassword)
	user.UpdatedAt = time.Now()

	return s.userRepo.Update(user)
}

func (s *UserService) UpdatePhoneNumber(userID uuid.UUID, phoneNumber string) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return err
	}

	// Format phone number (add + if missing, etc.)
	if twilioSvc, ok := s.smsSvc.(*sms.TwilioSMSService); ok {
		phoneNumber = twilioSvc.FormatPhoneNumber(phoneNumber)
	}

	// Reset verification status when phone number changes
	user.PhoneNumber = &phoneNumber
	user.IsPhoneVerified = false
	user.UpdatedAt = time.Now()

	return s.userRepo.Update(user)
}

// Session Management
func (s *UserService) Logout(token string) error {
	return s.sessionRepo.Delete(token)
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

func (s *UserService) generateSecureToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	hash := sha256.Sum256(bytes)
	return hex.EncodeToString(hash[:])
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
		"exp":     time.Now().Add(10 * time.Minute).Unix(),
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
