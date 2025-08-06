package main

import (
	"log"

	"github.com/auth-system/internal/application/service"
	"github.com/auth-system/internal/config"
	"github.com/auth-system/internal/infrastructure/database"
	"github.com/auth-system/internal/infrastructure/email"
	"github.com/auth-system/internal/infrastructure/repository"
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

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	otpRepo := repository.NewOTPRepository(db)
	sessionRepo := repository.NewSessionRepository(db)

	// Initialize services
	userService := service.NewUserService(userRepo, otpRepo, sessionRepo, emailService, cfg.JWTSecret)

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

	// Initialize routes
	routes.SetupRoutes(router, authHandler, middleware.AuthMiddleware(cfg.JWTSecret))

	log.Printf("Server starting on port %s", cfg.Port)
	log.Fatal(router.Run(":" + cfg.Port))
}
