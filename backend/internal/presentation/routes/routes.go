package routes

import (
	"github.com/auth-system/internal/presentation/handler"
	"github.com/gin-gonic/gin"
)

func SetupRoutes(router *gin.Engine, authHandler *handler.AuthHandler, authMiddleware gin.HandlerFunc) {
	api := router.Group("/api/v1")

	// Public routes
	auth := api.Group("/auth")
	{
		auth.POST("/register", authHandler.Register)
		auth.POST("/login", authHandler.Login)

		auth.POST("/verify-email", authHandler.VerifyEmail)
		auth.POST("/resend-verification", authHandler.ResendVerificationEmail)

		auth.POST("/send-mfa-code", authHandler.SendMFACode)
		auth.POST("/verify-mfa", authHandler.VerifyMFA)

		auth.POST("/forgot-password", authHandler.ForgotPassword)
		auth.POST("/reset-password", authHandler.ResetPassword)
	}

	// Protected routes
	protected := api.Group("/")
	protected.Use(authMiddleware)
	{
		// User profile routes
		protected.GET("/profile", authHandler.GetProfile)
		protected.POST("/logout", authHandler.Logout)
		protected.POST("/change-password", authHandler.ChangePassword)

		// Phone verification routes
		phone := protected.Group("/phone")
		{
			phone.POST("/update", authHandler.UpdatePhoneNumber)
			phone.POST("/send-verification", authHandler.SendPhoneVerification)
			phone.POST("/verify", authHandler.VerifyPhone)
		}

		// MFA management routes
		mfa := protected.Group("/mfa")
		{
			mfa.POST("/setup", authHandler.SetupMFA)
			mfa.POST("/enable", authHandler.EnableMFA)
			mfa.POST("/disable", authHandler.DisableMFA)
		}
	}
}
