// @title           GoVPN API Enhanced
// @version         1.1.0
// @description     OpenVPN Access Server Management API with Bulk Operations and Advanced Search
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.url    http://www.swagger.io/support
// @contact.email  support@swagger.io

// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html

// @host      localhost:8080
// @BasePath  /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and RSA256 JWT token.

package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"govpn/internal/application/handlers"
	"govpn/internal/application/middleware"
	"govpn/internal/domain/usecases"
	"govpn/internal/infrastructure/ldap"
	"govpn/internal/infrastructure/repositories"
	"govpn/internal/infrastructure/xmlrpc"
	httpRouter "govpn/internal/presentation/http"
	"govpn/pkg/config"
	"govpn/pkg/jwt"
	"govpn/pkg/logger"

	_ "govpn/docs" // Import generated docs
)

// JWTServiceInterface defines the interface for JWT operations
type JWTServiceInterface interface {
	GenerateAccessToken(username, role string) (string, error)
	GenerateRefreshToken(username, role string) (string, error)
	ValidateAccessToken(tokenString string) (*jwt.Claims, error)
	ValidateRefreshToken(tokenString string) (*jwt.Claims, error)
}

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	// Initialize logger
	loggerConfig := logger.LoggerConfig{
		Level:    cfg.Logger.Level,
		Format:   cfg.Logger.Format,
		FilePath: cfg.Logger.FilePath,
	}
	logger.Init(loggerConfig)

	// Log startup information
	logger.Log.Info("Starting GoVPN API Enhanced v1.1.0")
	logger.Log.Info("New Features: Bulk Operations, Advanced Search, File Import/Export")

	// Log JWT configuration mode
	if cfg.JWT.UseRSA {
		logger.Log.Info("Starting GoVPN API with RSA256 JWT authentication")
	} else {
		logger.Log.Warn("Starting GoVPN API with legacy HMAC256 JWT authentication")
	}

	// Initialize shared JWT service
	jwtService, err := initializeJWTService(cfg.JWT)
	if err != nil {
		log.Fatal("Failed to initialize JWT service:", err)
	}

	// Initialize infrastructure
	xmlrpcConfig := xmlrpc.Config{
		Host:     cfg.OpenVPN.Host,
		Username: cfg.OpenVPN.Username,
		Password: cfg.OpenVPN.Password,
		Port:     cfg.OpenVPN.Port,
	}
	xmlrpcClient := xmlrpc.NewClient(xmlrpcConfig)

	ldapConfig := ldap.Config{
		Host:         cfg.LDAP.Host,
		Port:         cfg.LDAP.Port,
		BindDN:       cfg.LDAP.BindDN,
		BindPassword: cfg.LDAP.BindPassword,
		BaseDN:       cfg.LDAP.BaseDN,
	}
	ldapClient := ldap.NewClient(ldapConfig)

	// Initialize repositories
	userRepo := repositories.NewUserRepository(xmlrpcClient)
	groupRepo := repositories.NewGroupRepository(xmlrpcClient)
	disconnectRepo := repositories.NewDisconnectRepository(xmlrpcClient)
	vpnStatusRepo := repositories.NewVPNStatusRepository(xmlrpcClient)

	// Initialize use cases with shared JWT service
	authUsecase := usecases.NewAuthUsecaseWithJWTService(userRepo, ldapClient, jwtService)
	userUsecase := usecases.NewUserUsecase(userRepo, groupRepo, ldapClient)
	groupUsecase := usecases.NewGroupUsecase(groupRepo)
	disconnectUsecase := usecases.NewDisconnectUsecase(userRepo, disconnectRepo, vpnStatusRepo)
	vpnStatusUsecase := usecases.NewVPNStatusUsecase(vpnStatusRepo)
	// NEW: Initialize bulk and search use cases
	bulkUsecase := usecases.NewBulkUsecase(userRepo, groupRepo, ldapClient)
	searchUsecase := usecases.NewSearchUsecase(userRepo, groupRepo)

	// Initialize middleware with shared JWT service
	authMiddleware := middleware.NewAuthMiddlewareWithJWTService(jwtService)
	corsMiddleware := middleware.NewCorsMiddleware()

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authUsecase)
	userHandler := handlers.NewUserHandler(userUsecase, xmlrpcClient)
	groupHandler := handlers.NewGroupHandler(groupUsecase, xmlrpcClient)

	// NEW: Initialize bulk and search handlers
	bulkHandler := handlers.NewBulkHandler(bulkUsecase, xmlrpcClient)
	searchHandler := handlers.NewSearchHandler(searchUsecase)
	vpnStatusHandler := handlers.NewVPNStatusHandler(vpnStatusUsecase)
	disconnectHandler := handlers.NewDisconnectHandler(disconnectUsecase)
	// Initialize router with new handlers
	router := httpRouter.NewRouterUpdated(
		authHandler,
		userHandler,
		groupHandler,
		bulkHandler,   // NEW: Bulk operations handler
		searchHandler, // NEW: Advanced search handler
		authMiddleware,
		corsMiddleware,
		vpnStatusHandler,
		disconnectHandler,
	)

	// Start server
	server := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      router.SetupRoutes(),
		ReadTimeout:  30 * time.Second, // Increased for file uploads
		WriteTimeout: 30 * time.Second, // Increased for bulk operations
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		logger.Log.Info("Server starting on port " + cfg.Server.Port)
		logger.Log.Info("Swagger UI available at: http://localhost:" + cfg.Server.Port + "/swagger/index.html")

		// Log feature information
		logger.Log.Info("✅ Basic User/Group Management")
		logger.Log.Info("✅ RSA256 JWT Authentication")
		logger.Log.Info("🆕 Bulk Operations:")
		logger.Log.Info("   - Bulk user creation (up to 100 users)")
		logger.Log.Info("   - Bulk group creation (up to 50 groups)")
		logger.Log.Info("   - Bulk actions (enable/disable/reset-otp)")
		logger.Log.Info("   - Bulk expiration extension")
		logger.Log.Info("🆕 File Import/Export:")
		logger.Log.Info("   - CSV/JSON/XLSX import with validation")
		logger.Log.Info("   - Template generation")
		logger.Log.Info("   - Dry-run mode for testing")
		logger.Log.Info("🆕 Advanced Search:")
		logger.Log.Info("   - Complex filters and sorting")
		logger.Log.Info("   - Saved searches")
		logger.Log.Info("   - Search suggestions and autocomplete")
		logger.Log.Info("   - Search analytics and statistics")
		logger.Log.Info("   - Export search results")

		if cfg.JWT.UseRSA {
			logger.Log.Info("Using RSA256 JWT tokens for enhanced security")
		} else {
			logger.Log.Warn("Using HMAC256 JWT tokens - consider upgrading to RSA256 for production")
		}

		// Log new API endpoints
		logger.Log.Info("🔗 New API Endpoints:")
		logger.Log.Info("Bulk Operations:")
		logger.Log.Info("  POST /api/bulk/users/create")
		logger.Log.Info("  POST /api/bulk/users/actions")
		logger.Log.Info("  POST /api/bulk/users/extend")
		logger.Log.Info("  POST /api/bulk/users/import")
		logger.Log.Info("  GET  /api/bulk/users/template")
		logger.Log.Info("  POST /api/bulk/groups/create")
		logger.Log.Info("  POST /api/bulk/groups/actions")
		logger.Log.Info("  POST /api/bulk/groups/import")
		logger.Log.Info("  GET  /api/bulk/groups/template")
		logger.Log.Info("Advanced Search:")
		logger.Log.Info("  POST /api/search/users")
		logger.Log.Info("  POST /api/search/groups")
		logger.Log.Info("  GET  /api/search/quick")
		logger.Log.Info("  POST /api/search/suggestions")
		logger.Log.Info("  POST /api/search/export")
		logger.Log.Info("  GET  /api/search/analytics")
		logger.Log.Info("  POST /api/search/saved")
		logger.Log.Info("  GET  /api/search/saved")

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Log.Fatal("Server failed to start:", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Log.Info("Server shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Log.Fatal("Server forced to shutdown:", err)
	}

	logger.Log.Info("GoVPN API Enhanced v1.1.0 exited gracefully")
}

// initializeJWTService creates a single JWT service instance to be shared
func initializeJWTService(jwtConfig config.JWTConfig) (JWTServiceInterface, error) {
	var jwtService JWTServiceInterface

	if jwtConfig.UseRSA {
		// Use RSA JWT service
		if jwtConfig.AccessPrivateKey != "" && jwtConfig.RefreshPrivateKey != "" {
			// Use provided RSA keys
			rsaService, err := jwt.NewRSAServiceWithKeys(
				jwtConfig.AccessPrivateKey,
				jwtConfig.RefreshPrivateKey,
				jwtConfig.AccessTokenExpireDuration,
				jwtConfig.RefreshTokenExpireDuration,
			)
			if err != nil {
				logger.Log.WithError(err).Error("Failed to create RSA JWT service with provided keys, falling back to generated keys")
				// Fallback to generated keys
				rsaService, err = jwt.NewRSAService(
					jwtConfig.AccessTokenExpireDuration,
					jwtConfig.RefreshTokenExpireDuration,
				)
				if err != nil {
					return nil, err
				}
			}
			jwtService = rsaService
			logger.Log.Info("JWT service using RSA256 with provided keys")
		} else {
			// Generate new RSA keys
			rsaService, err := jwt.NewRSAService(
				jwtConfig.AccessTokenExpireDuration,
				jwtConfig.RefreshTokenExpireDuration,
			)
			if err != nil {
				return nil, err
			}
			jwtService = rsaService
			logger.Log.Info("JWT service using RSA256 with generated keys")

			// Log the public keys for external verification (optional)
			if accessPubKey, err := rsaService.GetAccessPublicKeyPEM(); err == nil {
				logger.Log.Debug("Access token public key available for verification")
				// In production, you might want to save this to a file or database
				_ = accessPubKey // Placeholder to avoid unused variable
			}
		}
	} else {
		// Use legacy HMAC JWT service
		hmacService := jwt.NewService(
			jwtConfig.Secret,
			jwtConfig.RefreshSecret,
			jwtConfig.AccessTokenExpireDuration,
			jwtConfig.RefreshTokenExpireDuration,
		)
		jwtService = hmacService
		logger.Log.Warn("JWT service using legacy HMAC256. Consider migrating to RSA256 for better security.")
	}

	return jwtService, nil
}
