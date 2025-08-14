package main

import (
	"log"

	"github.com/auth-system/internal/application/service"
	"github.com/auth-system/internal/config"
	"github.com/auth-system/internal/infrastructure/cache"
	"github.com/auth-system/internal/infrastructure/database"
	"github.com/auth-system/internal/infrastructure/email"
	"github.com/auth-system/internal/infrastructure/repository"
	"github.com/auth-system/internal/infrastructure/sms"
	"github.com/auth-system/internal/presentation/handler"
	"github.com/auth-system/internal/presentation/middleware"
	"github.com/auth-system/internal/presentation/routes"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize database
	db, err := database.NewPostgresDB(cfg.DatabaseURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	// Run migrations
	if err := database.RunMigrations(db); err != nil {
		log.Fatal("Failed to run migrations:", err)
	}

	// Initialize email service
	emailService := email.NewSMTPEmailService(cfg.SMTPConfig)

	// Initialize Redis cache properly
	redisCache := cache.NewRedisCache(cfg.RedisConfig.URL, cfg.RedisConfig.Password, cfg.RedisConfig.DB)

	// Initialize SMS service properly with Twilio config
	smsService := sms.NewTwilioSMSService(
		cfg.TwilioConfig.AccountSID,
		cfg.TwilioConfig.AuthToken,
		cfg.TwilioConfig.FromNumber,
	)

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	otpRepo := repository.NewOTPRepository(db)
	sessionRepo := repository.NewSessionRepository(db)
	resetTokenRepo := repository.NewResetTokenRepository(db)
	rateLimitRepo := repository.NewRateLimitRepository(db)

	baseURL := "http://localhost:" + cfg.Port // Base URL for the application

	// Initialize services
	userService := service.NewUserService(
		userRepo,
		otpRepo,
		sessionRepo,
		resetTokenRepo,
		rateLimitRepo,
		emailService,
		smsService,
		redisCache,
		cfg.JWTSecret,
		baseURL,
	)

	// Initialize handlers
	authHandler := handler.NewAuthHandler(userService)

	// Initialize Gin router
	router := gin.Default()

	// CORS middleware
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"*"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":        "ok",
			"sms_enabled":   smsService.IsEnabled(),
			"twilio_config": cfg.TwilioConfig.Enabled,
		})
	})

	// Initialize routes
	routes.SetupRoutes(router, authHandler, middleware.AuthMiddleware(cfg.JWTSecret))

	log.Printf("Server starting on port %s", cfg.Port)
	log.Printf("SMS Service Enabled: %v", smsService.IsEnabled())
	log.Fatal(router.Run(":" + cfg.Port))
}
