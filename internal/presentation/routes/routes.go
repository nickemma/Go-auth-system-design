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
		auth.POST("/verify-mfa", authHandler.VerifyMFA)
		auth.POST("/forgot-password", authHandler.ForgotPassword)
	}

	// Protected routes
	protected := api.Group("/")
	protected.Use(authMiddleware)
	{
		protected.GET("/profile", authHandler.GetProfile)
		protected.POST("/logout", authHandler.Logout)
		protected.POST("/reset-password", authHandler.ResetPassword)

		mfa := protected.Group("/mfa")
		{
			mfa.POST("/setup", authHandler.SetupMFA)
			mfa.POST("/enable", authHandler.EnableMFA)
			mfa.POST("/disable", authHandler.DisableMFA)
		}
	}
}
