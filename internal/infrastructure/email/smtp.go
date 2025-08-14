package email

import (
	"fmt"
	"strconv"

	"github.com/auth-system/internal/config"
	"gopkg.in/gomail.v2"
)

type EmailService interface {
	SendOTP(to, otp string, otpType string) error
	SendMFABackupCodes(to string, codes []string) error
	SendPasswordResetLink(to, resetURL string) error
}

type smtpEmailService struct {
	config config.SMTPConfig
}

func NewSMTPEmailService(config config.SMTPConfig) EmailService {
	return &smtpEmailService{config: config}
}

func (s *smtpEmailService) SendOTP(to, otp string, otpType string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", s.config.From)
	m.SetHeader("To", to)

	var subject, body string
	switch otpType {
	case "email_verification":
		subject = "Email Verification Code"
		body = fmt.Sprintf("Your email verification code is: %s\n\nThis code will expire in 10 minutes.", otp)
	case "password_reset":
		subject = "Password Reset Code"
		body = fmt.Sprintf("Your password reset code is: %s\n\nThis code will expire in 10 minutes.", otp)
	case "login":
		subject = "Login Verification Code"
		body = fmt.Sprintf("Your login verification code is: %s\n\nThis code will expire in 5 minutes.", otp)
	default:
		subject = "Verification Code"
		body = fmt.Sprintf("Your verification code is: %s", otp)
	}

	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", body)

	port, _ := strconv.Atoi(s.config.Port)
	d := gomail.NewDialer(s.config.Host, port, s.config.Username, s.config.Password)

	return d.DialAndSend(m)
}

func (s *smtpEmailService) SendMFABackupCodes(to string, codes []string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", s.config.From)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "MFA Backup Codes")

	body := "Your MFA backup codes are:\n\n"
	for i, code := range codes {
		body += fmt.Sprintf("%d. %s\n", i+1, code)
	}
	body += "\nPlease store these codes in a safe place. Each code can only be used once."

	m.SetBody("text/plain", body)

	port, _ := strconv.Atoi(s.config.Port)
	d := gomail.NewDialer(s.config.Host, port, s.config.Username, s.config.Password)

	return d.DialAndSend(m)
}

func (s *smtpEmailService) SendPasswordResetLink(to, resetURL string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", s.config.From)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Password Reset Link")

	body := fmt.Sprintf("Click the following link to reset your password:\n\n%s\n\nThis link will expire in 1 hour.\n\nIf you did not request this reset, please ignore this email.", resetURL)

	m.SetBody("text/plain", body)

	port, _ := strconv.Atoi(s.config.Port)
	d := gomail.NewDialer(s.config.Host, port, s.config.Username, s.config.Password)

	return d.DialAndSend(m)
}
