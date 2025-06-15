package http

import (
	"govpn/internal/application/handlers"
	"govpn/internal/application/middleware"
	"time"

	"github.com/gin-contrib/timeout"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

type RouterUpdated struct {
	authHandler       *handlers.AuthHandler
	userHandler       *handlers.UserHandler
	groupHandler      *handlers.GroupHandler
	bulkHandler       *handlers.BulkHandler   // NEW: Bulk operations handler
	searchHandler     *handlers.SearchHandler // NEW: Advanced search handler
	authMiddleware    *middleware.AuthMiddleware
	corsMiddleware    *middleware.CorsMiddleware
	vpnStatusHandler  *handlers.VPNStatusHandler
	disconnectHandler *handlers.DisconnectHandler
	configHandler     *handlers.ConfigHandler
}

func NewRouterUpdated(
	authHandler *handlers.AuthHandler,
	userHandler *handlers.UserHandler,
	groupHandler *handlers.GroupHandler,
	bulkHandler *handlers.BulkHandler, // NEW: Bulk handler injection
	searchHandler *handlers.SearchHandler, // NEW: Search handler injection
	authMiddleware *middleware.AuthMiddleware,
	corsMiddleware *middleware.CorsMiddleware,
	vpnStatusHandler *handlers.VPNStatusHandler,
	disconnectHandler *handlers.DisconnectHandler,
	configHandler *handlers.ConfigHandler, // NEW: Config handler injection

) *RouterUpdated {
	return &RouterUpdated{
		authHandler:       authHandler,
		userHandler:       userHandler,
		groupHandler:      groupHandler,
		bulkHandler:       bulkHandler,   // NEW
		searchHandler:     searchHandler, // NEW
		authMiddleware:    authMiddleware,
		corsMiddleware:    corsMiddleware,
		vpnStatusHandler:  vpnStatusHandler,
		disconnectHandler: disconnectHandler,
		configHandler:     configHandler, // NEW
	}
}

func (r *RouterUpdated) SetupRoutes() *gin.Engine {
	// Set Gin mode
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()

	// ✅ FIX: Disable automatic redirect for trailing slash to fix 301 issue
	router.RedirectTrailingSlash = false
	router.RedirectFixedPath = false

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

func (r *RouterUpdated) setupPublicRoutes(router *gin.Engine) {
	// Swagger endpoint - available without authentication
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Authentication routes
	auth := router.Group("/auth")
	{
		auth.POST("/login", r.authHandler.Login)
		auth.POST("/refresh", r.authHandler.RefreshToken)
	}
}

func (r *RouterUpdated) setupProtectedRoutes(router *gin.Engine) {
	// Protected routes that require authentication
	protected := router.Group("/")
	protected.Use(r.authMiddleware.RequireAuth())
	{
		// Auth validation
		protected.GET("/auth/validate", r.authHandler.ValidateToken)

		// API routes
		api := protected.Group("/api")
		{
			// =================== EXISTING USER ROUTES ===================
			// ✅ FIX: Register both with and without trailing slash to handle both cases
			users := api.Group("/users")
			{
				// Basic CRUD operations - supporting both /users and /users/
				users.POST("", r.userHandler.CreateUser)
				users.POST("/", r.userHandler.CreateUser)
				users.GET("", r.userHandler.ListUsers)
				users.GET("/", r.userHandler.ListUsers)

				// Specific endpoints
				users.GET("/expirations", r.userHandler.GetUserExpirations)
				users.GET("/:username", r.userHandler.GetUser)
				users.PUT("/:username", r.userHandler.UpdateUser)
				users.DELETE("/:username", r.userHandler.DeleteUser)
				users.PUT("/:username/:action", r.userHandler.UserAction)
				users.POST("/:username/disconnect", r.disconnectHandler.DisconnectUser)
			}

			// =================== EXISTING GROUP ROUTES ===================
			// ✅ FIX: Register both with and without trailing slash to handle both cases
			groups := api.Group("/groups")
			{
				// Basic CRUD operations - supporting both /groups and /groups/
				groups.POST("", r.groupHandler.CreateGroup)
				groups.POST("/", r.groupHandler.CreateGroup)
				groups.GET("", r.groupHandler.ListGroups)
				groups.GET("/", r.groupHandler.ListGroups)

				// Specific endpoints
				groups.GET("/:groupName", r.groupHandler.GetGroup)
				groups.PUT("/:groupName", r.groupHandler.UpdateGroup)
				groups.DELETE("/:groupName", r.groupHandler.DeleteGroup)
				groups.PUT("/:groupName/:action", r.groupHandler.GroupAction)
			}

			// =================== NEW BULK OPERATIONS ROUTES ===================
			bulk := api.Group("/bulk")
			{
				// User bulk operations
				userBulk := bulk.Group("/users")
				{
					userBulk.POST("/create", r.bulkHandler.BulkCreateUsers)
					userBulk.POST("/actions", r.bulkHandler.BulkUserActions)
					userBulk.POST("/extend", r.bulkHandler.BulkExtendUsers)
					userBulk.POST("/import", r.bulkHandler.ImportUsers)
					userBulk.GET("/template", r.bulkHandler.ExportUserTemplate)
					userBulk.POST("/disconnect", r.disconnectHandler.BulkDisconnectUsers)
				}

				// Group bulk operations
				groupBulk := bulk.Group("/groups")
				{
					groupBulk.POST("/create", r.bulkHandler.BulkCreateGroups)
					groupBulk.POST("/actions", r.bulkHandler.BulkGroupActions)
					groupBulk.POST("/import", r.bulkHandler.ImportGroups)
					groupBulk.GET("/template", r.bulkHandler.ExportGroupTemplate)
				}
			}

			// =================== NEW ADVANCED SEARCH ROUTES ===================
			search := api.Group("/search")
			{
				// Advanced search endpoints
				search.POST("/users", r.searchHandler.AdvancedUserSearch)
				search.POST("/groups", r.searchHandler.AdvancedGroupSearch)

				// Quick search
				search.GET("/quick", r.searchHandler.QuickSearch)

				// Search suggestions and autocomplete
				search.POST("/suggestions", r.searchHandler.GetSearchSuggestions)

				// Export search results
				search.POST("/export", r.searchHandler.ExportSearchResults)

				// Search analytics
				search.GET("/analytics", r.searchHandler.GetSearchAnalytics)

				// Saved searches management
				saved := search.Group("/saved")
				{
					saved.POST("/", r.searchHandler.SaveSearch)
					saved.GET("/", r.searchHandler.GetSavedSearches)
					saved.GET("/:searchId/execute", r.searchHandler.ExecuteSavedSearch)
					saved.DELETE("/:searchId", r.searchHandler.DeleteSavedSearch)
				}
			}
			vpn := api.Group("/vpn")
			{
				vpn.GET("/status", r.vpnStatusHandler.GetVPNStatus)
			}
			config := api.Group("/config")
			{
				server := config.Group("/server")
				{
					server.GET("/info", r.configHandler.GetServerInfo)
				}
				config.GET("/network", r.configHandler.GetNetworkConfig)
			}
		}
	}
}

func (r *RouterUpdated) healthCheck(c *gin.Context) {
	// Use helper function from handlers package
	handlers.RespondWithSuccess(c, 200, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"service":   "govpn-api",
		"version":   "1.1.0", // Updated version
		"features": []string{
			"bulk-operations",
			"advanced-search",
			"file-import",
			"search-analytics",
		},
	})
}

func (r *RouterUpdated) apiInfo(c *gin.Context) {
	// Use helper function from handlers package
	handlers.RespondWithSuccess(c, 200, gin.H{
		"service":     "GoVPN API",
		"version":     "1.1.0", // Updated version
		"description": "OpenVPN Access Server Management API with Bulk Operations and Advanced Search",
		"features": gin.H{
			"bulk_operations": gin.H{
				"description":       "Create, manage, and import multiple users/groups",
				"supported_formats": []string{"CSV", "JSON", "XLSX"},
				"max_batch_size": gin.H{
					"users":  100,
					"groups": 50,
				},
			},
			"advanced_search": gin.H{
				"description": "Complex search with filters, sorting, and analytics",
				"features": []string{
					"date_ranges", "status_filters", "pattern_matching",
					"saved_searches", "autocomplete", "export",
				},
			},
		},
		"endpoints": gin.H{
			"swagger": gin.H{
				"ui":   "/swagger/index.html",
				"json": "/swagger/doc.json",
			},
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
				"disconnect":  "POST /api/users/{username}/disconnect",
			},
			"groups": gin.H{
				"create": "POST /api/groups",
				"list":   "GET /api/groups",
				"get":    "GET /api/groups/{groupName}",
				"update": "PUT /api/groups/{groupName}",
				"delete": "DELETE /api/groups/{groupName}",
				"action": "PUT /api/groups/{groupName}/{action}",
			},
			// NEW: Bulk operations endpoints
			"bulk_operations": gin.H{
				"users": gin.H{
					"bulk_create":     "POST /api/bulk/users/create",
					"bulk_actions":    "POST /api/bulk/users/actions",
					"bulk_extend":     "POST /api/bulk/users/extend",
					"import":          "POST /api/bulk/users/import",
					"template":        "GET /api/bulk/users/template",
					"bulk_disconnect": "POST /api/bulk/users/disconnect",
				},
				"groups": gin.H{
					"bulk_create":  "POST /api/bulk/groups/create",
					"bulk_actions": "POST /api/bulk/groups/actions",
					"import":       "POST /api/bulk/groups/import",
					"template":     "GET /api/bulk/groups/template",
				},
			},
			// NEW: Advanced search endpoints
			"advanced_search": gin.H{
				"user_search":    "POST /api/search/users",
				"group_search":   "POST /api/search/groups",
				"quick_search":   "GET /api/search/quick",
				"suggestions":    "POST /api/search/suggestions",
				"export_results": "POST /api/search/export",
				"analytics":      "GET /api/search/analytics",
				"saved_searches": gin.H{
					"save":    "POST /api/search/saved",
					"list":    "GET /api/search/saved",
					"execute": "GET /api/search/saved/{id}/execute",
					"delete":  "DELETE /api/search/saved/{id}",
				},
			},
			"vpn_status": gin.H{
				"get_status": "GET /api/vpn/status",
			},
			"config": gin.H{
				"server_info":  "GET /api/config/server/info",
				"network_info": "GET /api/config/network",
			},
		},
		"documentation": "/swagger/index.html",
	})
}
