package http

import (
	"govpn/internal/application/handlers"
	"govpn/internal/application/middleware"
	"time"

	"github.com/gin-contrib/timeout"
	"github.com/gin-gonic/gin"
)

type Router struct {
	authHandler    *handlers.AuthHandler
	userHandler    *handlers.UserHandler
	groupHandler   *handlers.GroupHandler
	authMiddleware *middleware.AuthMiddleware
	corsMiddleware *middleware.CorsMiddleware
}

func NewRouter(
	authHandler *handlers.AuthHandler,
	userHandler *handlers.UserHandler,
	groupHandler *handlers.GroupHandler,
	authMiddleware *middleware.AuthMiddleware,
	corsMiddleware *middleware.CorsMiddleware,
) *Router {
	return &Router{
		authHandler:    authHandler,
		userHandler:    userHandler,
		groupHandler:   groupHandler,
		authMiddleware: authMiddleware,
		corsMiddleware: corsMiddleware,
	}
}

func (r *Router) SetupRoutes() *gin.Engine {
	// Set Gin mode
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()

	// Global middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(r.corsMiddleware.Handler())
	router.Use(r.corsMiddleware.SecurityHeaders())

	// Timeout middleware
	router.Use(timeout.New(
		timeout.WithTimeout(30*time.Second),
		timeout.WithHandler(func(c *gin.Context) {
			c.Next()
		}),
	))

	// Health check endpoint
	router.GET("/health", r.healthCheck)

	// API documentation
	router.GET("/", r.apiInfo)

	// Public routes (no authentication required)
	r.setupPublicRoutes(router)

	// Protected routes (authentication required)
	r.setupProtectedRoutes(router)

	return router
}

func (r *Router) setupPublicRoutes(router *gin.Engine) {
	// Authentication routes
	auth := router.Group("/auth")
	{
		auth.POST("/login", r.authHandler.Login)
		auth.POST("/refresh", r.authHandler.RefreshToken)
	}
}

func (r *Router) setupProtectedRoutes(router *gin.Engine) {
	// Protected routes that require authentication
	protected := router.Group("/")
	protected.Use(r.authMiddleware.RequireAuth())
	{
		// Auth validation
		protected.GET("/auth/validate", r.authHandler.ValidateToken)

		// API routes
		api := protected.Group("/api")
		{
			// User routes
			users := api.Group("/users")
			{
				users.POST("/", r.userHandler.CreateUser)
				users.GET("/", r.userHandler.ListUsers)
				users.GET("/expirations", r.userHandler.GetUserExpirations)
				users.GET("/:username", r.userHandler.GetUser)
				users.PUT("/:username", r.userHandler.UpdateUser)
				users.DELETE("/:username", r.userHandler.DeleteUser)
				users.PUT("/:username/:action", r.userHandler.UserAction)
			}

			// Group routes
			groups := api.Group("/groups")
			{
				groups.POST("/", r.groupHandler.CreateGroup)
				groups.GET("/", r.groupHandler.ListGroups)
				groups.GET("/:groupName", r.groupHandler.GetGroup)
				groups.PUT("/:groupName", r.groupHandler.UpdateGroup)
				groups.DELETE("/:groupName", r.groupHandler.DeleteGroup)
				groups.PUT("/:groupName/:action", r.groupHandler.GroupAction)
			}
		}
	}
}

func (r *Router) healthCheck(c *gin.Context) {
	RespondWithSuccess(c, 200, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"service":   "govpn-api",
	})
}

func (r *Router) apiInfo(c *gin.Context) {
	RespondWithSuccess(c, 200, gin.H{
		"service":     "GoVPN API",
		"version":     "1.0.0",
		"description": "OpenVPN Access Server Management API",
		"endpoints": gin.H{
			"auth": gin.H{
				"login":    "POST /auth/login",
				"refresh":  "POST /auth/refresh",
				"validate": "GET /auth/validate",
			},
			"users": gin.H{
				"create":      "POST /api/users",
				"list":        "GET /api/users",
				"get":         "GET /api/users/{username}",
				"update":      "PUT /api/users/{username}",
				"delete":      "DELETE /api/users/{username}",
				"action":      "PUT /api/users/{username}/{action}",
				"expirations": "GET /api/users/expirations",
			},
			"groups": gin.H{
				"create": "POST /api/groups",
				"list":   "GET /api/groups",
				"get":    "GET /api/groups/{groupName}",
				"update": "PUT /api/groups/{groupName}",
				"delete": "DELETE /api/groups/{groupName}",
				"action": "PUT /api/groups/{groupName}/{action}",
			},
		},
		"documentation": "/docs",
	})
}
