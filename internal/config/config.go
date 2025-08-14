package config

import (
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	Port         string
	DatabaseURL  string
	JWTSecret    string
	SMTPConfig   SMTPConfig
	TwilioConfig TwilioConfig
	RedisConfig  RedisConfig
}
type SMTPConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
}

type TwilioConfig struct {
	AccountSID string
	AuthToken  string
	FromNumber string
	Enabled    bool
}

type RedisConfig struct {
	Host     string
	Port     string
	Password string
	DB       int
	URL      string
}

func Load() *Config {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found or error loading .env:", err)
	}

	// Debug: Check if .env file exists
	if _, err := os.Stat(".env"); err == nil {
		log.Println(".env file exists in current directory")
	} else {
		log.Println(".env file not found in current directory:", err)
	}

	redisDB := 0
	if dbStr := getEnv("REDIS_DB", "0"); dbStr != "" {
		if db, err := strconv.Atoi(dbStr); err == nil {
			redisDB = db
		}
	}

	// Build Redis URL
	redisHost := getEnv("REDIS_HOST", "redis")
	redisPort := getEnv("REDIS_PORT", "6379")
	redisURL := getEnv("REDIS_URL", "redis://"+redisHost+":"+redisPort+"/0")

	// Twilio configuration - make it truly optional
	twilioAccountSID := getEnv("TWILIO_ACCOUNT_SID", "")
	twilioAuthToken := getEnv("TWILIO_AUTH_TOKEN", "")
	twilioFromNumber := getEnv("TWILIO_PHONE_NUMBER", "")

	// Twilio is enabled only if all required fields are present
	twilioEnabled := twilioAccountSID != "" && twilioAuthToken != "" && twilioFromNumber != ""

	// Get SMTP configuration with debug logging
	smtpHost := getEnv("SMTP_HOST", "smtp.gmail.com")
	smtpPort := getEnv("SMTP_PORT", "587")
	smtpUsername := getEnv("SMTP_USERNAME", "")
	smtpPassword := getEnv("SMTP_PASSWORD", "")
	smtpFrom := getEnv("SMTP_FROM", "noreply@example.com")

	// Debug SMTP configuration (mask password)
	log.Println("=== SMTP Configuration Debug ===")
	log.Printf("SMTP_HOST: %s", smtpHost)
	log.Printf("SMTP_PORT: %s", smtpPort)
	log.Printf("SMTP_USERNAME: %s", smtpUsername)
	log.Printf("SMTP_PASSWORD: %s", maskPassword(smtpPassword))
	log.Printf("SMTP_FROM: %s", smtpFrom)
	log.Println("================================")

	cfg := &Config{
		Port:        getEnv("PORT", "8080"),
		DatabaseURL: getEnv("DATABASE_URL", "postgres://postgres:password@postgres:5432/authdb?sslmode=disable"),
		JWTSecret:   getEnv("JWT_SECRET", ""),
		// Initialize smtp configuration
		SMTPConfig: SMTPConfig{
			Host:     smtpHost,
			Port:     smtpPort,
			Username: smtpUsername,
			Password: smtpPassword,
			From:     smtpFrom,
		},
		// Initialize Twilio configuration
		TwilioConfig: TwilioConfig{
			AccountSID: twilioAccountSID,
			AuthToken:  twilioAuthToken,
			FromNumber: twilioFromNumber,
			Enabled:    twilioEnabled,
		},
		// Initialize Redis configuration
		RedisConfig: RedisConfig{
			Host:     redisHost,
			Port:     redisPort,
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       redisDB,
			URL:      redisURL,
		},
	}

	// Validate required configurations
	if cfg.JWTSecret == "" {
		log.Fatal("JWT_SECRET is required but not set")
	}
	if cfg.SMTPConfig.Username == "" || cfg.SMTPConfig.Password == "" {
		log.Fatal("SMTP_USERNAME and SMTP_PASSWORD are required but not set")
	}
	// Only warn about Twilio if not configured
	if !cfg.TwilioConfig.Enabled {
		log.Println("WARNING: Twilio not configured. SMS features will be disabled.")
	} else {
		log.Println("Twilio configured successfully. SMS features enabled.")
	}

	return cfg
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Helper function to mask password for logging
func maskPassword(password string) string {
	if password == "" {
		return "not set"
	}
	if len(password) <= 4 {
		return "****"
	}
	return password[:2] + strings.Repeat("*", len(password)-4) + password[len(password)-2:]
}
