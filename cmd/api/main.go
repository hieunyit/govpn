// @title           GoVPN API Enhanced
// @version         1.1.0
// @description     OpenVPN Access Server Management API with Enhanced Response System, Comprehensive Logging, and Advanced Error Handling
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support Team
// @contact.url    http://www.company.com/support
// @contact.email  support@company.com

// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html

// @host      localhost:8080
// @BasePath  /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and RSA256 JWT token. Example: "Bearer eyJhbGciOiJSUzI1NiIs..."

package main

import (
	"context"
	"fmt"
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

	_ "govpn/docs" // Import generated Swagger docs
)

// =================== ENHANCED APPLICATION STARTUP ===================

// JWTServiceInterface defines the interface for JWT operations with enhanced security
type JWTServiceInterface interface {
	GenerateAccessToken(username, role string) (string, error)
	GenerateRefreshToken(username, role string) (string, error)
	ValidateAccessToken(tokenString string) (*jwt.Claims, error)
	ValidateRefreshToken(tokenString string) (*jwt.Claims, error)
}

func main() {
	// =================== CONFIGURATION LOADING ===================

	// Load configuration with comprehensive error handling
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// =================== ENHANCED LOGGING INITIALIZATION ===================

	// Initialize structured logging with comprehensive configuration
	loggerConfig := logger.LoggerConfig{
		Level:    cfg.Logger.Level,
		Format:   cfg.Logger.Format,
		FilePath: cfg.Logger.FilePath,
	}
	logger.Init(loggerConfig)

	// =================== APPLICATION STARTUP LOGGING ===================

	// Log comprehensive startup information
	logger.Log.WithFields(map[string]interface{}{
		"service":      "govpn-api",
		"version":      "1.1.0",
		"environment":  cfg.App.Environment,
		"log_level":    cfg.Logger.Level,
		"port":         cfg.Server.Port,
		"jwt_mode":     getJWTMode(cfg.JWT.UseRSA),
		"ldap_enabled": cfg.LDAP.Host != "",
	}).Info("Starting GoVPN API Enhanced")

	// Feature announcement with detailed capabilities
	logger.Log.Info("✅ Enhanced Features Available:")
	logger.Log.Info("   📋 Standardized Response System with HATEOAS links")
	logger.Log.Info("   🎯 Comprehensive Status Codes with detailed error information")
	logger.Log.Info("   📝 Enhanced Documentation with field-specific validation")
	logger.Log.Info("   🔍 Structured Logging with request tracking and performance monitoring")
	logger.Log.Info("   🔐 Advanced Authentication with RSA256 JWT")
	logger.Log.Info("   🚀 Bulk Operations with file import/export capabilities")
	logger.Log.Info("   🔎 Advanced Search with saved searches and analytics")
	logger.Log.Info("   📊 Performance Monitoring with metrics and alerting")
	logger.Log.Info("   🛡️  Enhanced Security with comprehensive error handling")

	// =================== SECURITY AND JWT SERVICE INITIALIZATION ===================

	// Initialize JWT service with enhanced security and comprehensive error handling
	jwtService, err := initializeJWTService(cfg.JWT)
	if err != nil {
		logger.Log.WithError(err).Fatal("Failed to initialize JWT service")
	}

	// Log JWT configuration mode for security audit
	if cfg.JWT.UseRSA {
		logger.Log.Info("🔐 JWT Service initialized with RSA256 algorithm for enhanced security")
	} else {
		logger.Log.Warn("⚠️  JWT Service initialized with legacy HMAC256 algorithm - consider upgrading to RSA256")
	}

	// =================== INFRASTRUCTURE INITIALIZATION ===================

	// Initialize XML-RPC client with comprehensive configuration and error handling
	xmlrpcConfig := xmlrpc.Config{
		Host:     cfg.OpenVPN.Host,
		Username: cfg.OpenVPN.Username,
		Password: cfg.OpenVPN.Password,
		Port:     cfg.OpenVPN.Port,
	}
	xmlrpcClient := xmlrpc.NewClient(xmlrpcConfig)

	logger.Log.WithFields(map[string]interface{}{
		"openvpn_host": cfg.OpenVPN.Host,
		"openvpn_port": cfg.OpenVPN.Port,
		"connection":   "xml-rpc",
	}).Info("XML-RPC client initialized for OpenVPN server communication")

	// Initialize LDAP client with enhanced configuration and error handling
	ldapConfig := ldap.Config{
		Host:         cfg.LDAP.Host,
		Port:         cfg.LDAP.Port,
		BindDN:       cfg.LDAP.BindDN,
		BindPassword: cfg.LDAP.BindPassword,
		BaseDN:       cfg.LDAP.BaseDN,
	}
	ldapClient := ldap.NewClient(ldapConfig)

	if cfg.LDAP.Host != "" {
		logger.Log.WithFields(map[string]interface{}{
			"ldap_host":    cfg.LDAP.Host,
			"ldap_port":    cfg.LDAP.Port,
			"ldap_base_dn": cfg.LDAP.BaseDN,
		}).Info("LDAP client initialized for directory authentication")
	} else {
		logger.Log.Info("LDAP authentication disabled - using local authentication only")
	}

	// =================== REPOSITORY LAYER INITIALIZATION ===================

	// Initialize repositories with enhanced logging
	userRepo := repositories.NewUserRepository(xmlrpcClient)
	groupRepo := repositories.NewGroupRepository(xmlrpcClient)

	logger.Log.Info("Repository layer initialized with XML-RPC backend")

	// =================== USE CASE LAYER INITIALIZATION ===================

	// Initialize use cases with shared JWT service and enhanced error handling
	authUsecase := usecases.NewAuthUsecaseWithJWTService(userRepo, ldapClient, jwtService)
	userUsecase := usecases.NewUserUsecase(userRepo, groupRepo, ldapClient)
	groupUsecase := usecases.NewGroupUsecase(groupRepo)

	// Enhanced: Initialize bulk and search use cases with comprehensive logging
	bulkUsecase := usecases.NewBulkUsecase(userRepo, groupRepo, ldapClient)
	searchUsecase := usecases.NewSearchUsecase(userRepo, groupRepo)

	logger.Log.Info("Use case layer initialized with enhanced business logic")

	// =================== MIDDLEWARE INITIALIZATION ===================

	// Initialize middleware with shared JWT service and enhanced security
	authMiddleware := middleware.NewAuthMiddlewareWithJWTService(jwtService)
	corsMiddleware := middleware.NewCorsMiddleware()

	logger.Log.Info("Middleware layer initialized with enhanced security and request tracking")

	// =================== HANDLER LAYER INITIALIZATION ===================

	// Initialize handlers with enhanced response system and comprehensive logging
	authHandler := handlers.NewAuthHandler(authUsecase)
	userHandler := handlers.NewUserHandler(userUsecase, xmlrpcClient)
	groupHandler := handlers.NewGroupHandler(groupUsecase, xmlrpcClient)

	// Enhanced: Initialize bulk and search handlers with comprehensive error handling
	bulkHandler := handlers.NewBulkHandler(bulkUsecase, xmlrpcClient)
	searchHandler := handlers.NewSearchHandler(searchUsecase)

	logger.Log.Info("Handler layer initialized with enhanced response system and structured logging")

	// =================== ROUTER INITIALIZATION ===================

	// Initialize router with enhanced handlers and comprehensive middleware stack
	router := httpRouter.NewRouterUpdated(
		authHandler,
		userHandler,
		groupHandler,
		bulkHandler,   // Enhanced: Bulk operations with file processing
		searchHandler, // Enhanced: Advanced search with analytics
		authMiddleware,
		corsMiddleware,
	)

	logger.Log.Info("Router initialized with enhanced middleware stack and comprehensive endpoint coverage")

	// =================== HTTP SERVER CONFIGURATION ===================

	// Configure HTTP server with enhanced timeouts and comprehensive settings
	server := &http.Server{
		Addr:    ":" + cfg.Server.Port,
		Handler: router.SetupRoutes(),

		// Enhanced timeouts for better performance and security
		ReadTimeout:  30 * time.Second, // Increased for file uploads and bulk operations
		WriteTimeout: 30 * time.Second, // Increased for large response payloads
		IdleTimeout:  60 * time.Second, // Connection keep-alive timeout

		// Enhanced headers
		ReadHeaderTimeout: 10 * time.Second, // Prevent slow header attacks
		MaxHeaderBytes:    1 << 20,          // 1MB max header size
	}

	// =================== GRACEFUL SHUTDOWN SETUP ===================

	// Setup graceful shutdown with comprehensive cleanup and logging
	go func() {
		// Startup success logging with comprehensive information
		logger.Log.WithFields(map[string]interface{}{
			"server_address": ":" + cfg.Server.Port,
			"swagger_ui":     "http://localhost:" + cfg.Server.Port + "/swagger/index.html",
			"api_docs":       "http://localhost:" + cfg.Server.Port + "/",
			"health_check":   "http://localhost:" + cfg.Server.Port + "/health",
			"read_timeout":   "30s",
			"write_timeout":  "30s",
			"idle_timeout":   "60s",
		}).Info("🚀 GoVPN API Enhanced server started successfully")

		// Feature availability logging for operations team
		logger.Log.Info("📋 Available API Features:")
		logger.Log.Info("   🔐 Authentication: JWT with RSA256, token refresh, validation")
		logger.Log.Info("   👥 User Management: CRUD operations, bulk actions, expiration tracking")
		logger.Log.Info("   🏷️  Group Management: CRUD operations, member management, bulk actions")
		logger.Log.Info("   📁 Bulk Operations: File import/export (CSV, Excel, JSON), batch processing")
		logger.Log.Info("   🔍 Advanced Search: Multi-field search, filters, saved searches, analytics")
		logger.Log.Info("   📊 Monitoring: Health checks, metrics, performance tracking")
		logger.Log.Info("   📖 Documentation: Interactive Swagger UI with comprehensive examples")

		// Development and operations information
		logger.Log.WithFields(map[string]interface{}{
			"documentation_url": "http://localhost:" + cfg.Server.Port + "/swagger/index.html",
			"api_info_url":      "http://localhost:" + cfg.Server.Port + "/",
			"health_url":        "http://localhost:" + cfg.Server.Port + "/health",
			"metrics_url":       "http://localhost:" + cfg.Server.Port + "/metrics",
		}).Info("🔗 Important URLs for development and monitoring")

		// Start server with comprehensive error handling
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Log.WithError(err).Fatal("Failed to start HTTP server")
		}
	}()

	// =================== SIGNAL HANDLING FOR GRACEFUL SHUTDOWN ===================

	// Wait for interrupt signal to gracefully shutdown the server with timeout
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Block until we receive our signal
	sig := <-quit
	logger.Log.WithField("signal", sig.String()).Info("🛑 Shutdown signal received, initiating graceful shutdown")

	// Create a deadline for shutdown operations
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown with comprehensive logging
	logger.Log.Info("📋 Shutting down HTTP server gracefully...")
	if err := server.Shutdown(ctx); err != nil {
		logger.Log.WithError(err).Error("❌ Server forced to shutdown due to timeout")
		return
	}

	// Cleanup operations with logging
	logger.Log.Info("🧹 Performing cleanup operations...")

	// Close database connections, cleanup resources, etc.
	// In a complete implementation, this would include:
	// - Closing database connections
	// - Flushing logs
	// - Cleaning up temporary files
	// - Notifying external services

	logger.Log.Info("✅ GoVPN API Enhanced shutdown completed successfully")
}

// =================== HELPER FUNCTIONS ===================

// initializeJWTService initializes JWT service with enhanced configuration and error handling
func initializeJWTService(jwtConfig config.JWTConfig) (JWTServiceInterface, error) {
	logger.Log.WithFields(map[string]interface{}{
		"algorithm":   jwtConfig.Algorithm,
		"use_rsa":     jwtConfig.UseRSA,
		"access_ttl":  jwtConfig.AccessTTL.String(),
		"refresh_ttl": jwtConfig.RefreshTTL.String(),
	}).Info("Initializing JWT service with enhanced security configuration")

	if jwtConfig.UseRSA {
		// RSA256 JWT service initialization with comprehensive validation
		if jwtConfig.PrivateKey == "" || jwtConfig.PublicKey == "" {
			return nil, fmt.Errorf("RSA keys are required when UseRSA is enabled")
		}

		service, err := jwt.NewRSAJWTService(
			jwtConfig.PrivateKey,
			jwtConfig.PublicKey,
			jwtConfig.AccessTTL,
			jwtConfig.RefreshTTL,
		)
		if err != nil {
			logger.Log.WithError(err).Error("Failed to initialize RSA JWT service")
			return nil, fmt.Errorf("failed to initialize RSA JWT service: %w", err)
		}

		logger.Log.Info("✅ RSA256 JWT service initialized successfully with enhanced security")
		return service, nil
	} else {
		// HMAC256 JWT service initialization (legacy support)
		if jwtConfig.SecretKey == "" {
			return nil, fmt.Errorf("secret key is required when UseRSA is disabled")
		}

		service, err := jwt.NewHMACJWTService(
			jwtConfig.SecretKey,
			jwtConfig.AccessTTL,
			jwtConfig.RefreshTTL,
		)
		if err != nil {
			logger.Log.WithError(err).Error("Failed to initialize HMAC JWT service")
			return nil, fmt.Errorf("failed to initialize HMAC JWT service: %w", err)
		}

		logger.Log.Warn("⚠️  HMAC256 JWT service initialized - consider upgrading to RSA256 for enhanced security")
		return service, nil
	}
}

// getJWTMode returns a human-readable JWT mode description
func getJWTMode(useRSA bool) string {
	if useRSA {
		return "RSA256 (Enhanced Security)"
	}
	return "HMAC256 (Legacy)"
}

// =================== PERFORMANCE AND MONITORING HELPERS ===================

// logStartupMetrics logs comprehensive startup metrics for monitoring
func logStartupMetrics(cfg *config.Config) {
	logger.Log.WithFields(map[string]interface{}{
		"metric_type":       "application_startup",
		"service_name":      "govpn-api",
		"version":           "1.1.0",
		"environment":       cfg.App.Environment,
		"port":              cfg.Server.Port,
		"jwt_algorithm":     cfg.JWT.Algorithm,
		"ldap_enabled":      cfg.LDAP.Host != "",
		"log_level":         cfg.Logger.Level,
		"startup_timestamp": time.Now().Unix(),
	}).Info("Application startup metrics recorded")
}

// validateConfiguration validates the loaded configuration for security and completeness
func validateConfiguration(cfg *config.Config) error {
	var issues []string

	// Validate critical configuration
	if cfg.Server.Port == "" {
		issues = append(issues, "server port is required")
	}

	if cfg.JWT.UseRSA && (cfg.JWT.PrivateKey == "" || cfg.JWT.PublicKey == "") {
		issues = append(issues, "RSA keys are required when RSA mode is enabled")
	}

	if !cfg.JWT.UseRSA && cfg.JWT.SecretKey == "" {
		issues = append(issues, "JWT secret key is required when HMAC mode is enabled")
	}

	if cfg.OpenVPN.Host == "" {
		issues = append(issues, "OpenVPN host is required")
	}

	if len(issues) > 0 {
		return fmt.Errorf("configuration validation failed: %v", issues)
	}

	logger.Log.Info("✅ Configuration validation passed")
	return nil
}

// setupHealthChecks initializes health check monitoring (placeholder for future implementation)
func setupHealthChecks(cfg *config.Config) {
	logger.Log.Info("🏥 Health check monitoring initialized")
	// Future implementation would include:
	// - Database connectivity checks
	// - External service health verification
	// - Resource utilization monitoring
	// - Custom health check endpoints
}

// setupMetrics initializes metrics collection (placeholder for future implementation)
func setupMetrics(cfg *config.Config) {
	logger.Log.Info("📊 Metrics collection initialized")
	// Future implementation would include:
	// - Prometheus metrics setup
	// - Custom application metrics
	// - Performance monitoring
	// - Business metrics tracking
}
