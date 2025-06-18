// @title           GoVPN API Enhanced with Advanced Redis Caching
// @version         1.2.0
// @description     OpenVPN Access Server Management API with Bulk Operations, Advanced Search, and Comprehensive Redis Caching
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
	"govpn/internal/domain/repositories"
	"govpn/internal/domain/usecases"
	"govpn/internal/infrastructure/ldap"
	"govpn/internal/infrastructure/redis"
	xmlrpcRepositories "govpn/internal/infrastructure/repositories"
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
	logger.Log.Info("Starting GoVPN API Enhanced v1.3.0")
	logger.Log.Info("Features: Advanced Redis Caching, Enhanced Performance, Filtered Queries")

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

	// Initialize Redis client
	redisClient, err := redis.NewClient(cfg.Redis)
	if err != nil {
		log.Fatal("Failed to initialize Redis client:", err)
	}
	defer redisClient.Close()

	logger.Log.WithField("enabled", cfg.Redis.Enabled).Info("Redis client initialized")

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

	// Initialize base repositories
	baseUserRepo := xmlrpcRepositories.NewUserRepository(xmlrpcClient)
	baseGroupRepo := xmlrpcRepositories.NewGroupRepository(xmlrpcClient)
	baseConfigRepo := xmlrpcRepositories.NewConfigRepository(xmlrpcClient)
	disconnectRepo := xmlrpcRepositories.NewDisconnectRepository(xmlrpcClient)
	vpnStatusRepo := xmlrpcRepositories.NewVPNStatusRepository(xmlrpcClient)

	// ✅ ENHANCED: Wrap repositories with caching if enabled
	var userRepo repositories.UserRepository
	var groupRepo repositories.GroupRepository
	var configRepo repositories.ConfigRepository

	if cfg.Redis.Enabled {
		userRepo = xmlrpcRepositories.NewCachedUserRepository(baseUserRepo, redisClient)
		groupRepo = xmlrpcRepositories.NewCachedGroupRepository(baseGroupRepo, redisClient)
		configRepo = xmlrpcRepositories.NewCachedConfigRepository(baseConfigRepo, redisClient) // ✅ NEW
		logger.Log.Info("All repositories wrapped with Redis caching (including config)")
	} else {
		userRepo = baseUserRepo
		groupRepo = baseGroupRepo
		configRepo = baseConfigRepo
		logger.Log.Info("Using direct repositories without caching")
	}

	// Initialize use cases with shared JWT service
	authUsecase := usecases.NewAuthUsecaseWithJWTService(userRepo, ldapClient, jwtService)
	userUsecase := usecases.NewUserUsecase(userRepo, groupRepo, ldapClient)
	groupUsecase := usecases.NewGroupUsecase(groupRepo, configRepo)
	disconnectUsecase := usecases.NewDisconnectUsecase(userRepo, disconnectRepo, vpnStatusRepo)
	vpnStatusUsecase := usecases.NewVPNStatusUsecase(vpnStatusRepo)
	configUsecase := usecases.NewConfigUsecase(configRepo) // ✅ Now using cached config repo
	bulkUsecase := usecases.NewBulkUsecase(userRepo, groupRepo, ldapClient)
	searchUsecase := usecases.NewSearchUsecase(userRepo, groupRepo)

	// Initialize middleware with shared JWT service
	authMiddleware := middleware.NewAuthMiddlewareWithJWTService(jwtService)
	corsMiddleware := middleware.NewCorsMiddleware()

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authUsecase)
	userHandler := handlers.NewUserHandler(userUsecase, xmlrpcClient)
	groupHandler := handlers.NewGroupHandler(groupUsecase, configUsecase, xmlrpcClient)
	bulkHandler := handlers.NewBulkHandler(bulkUsecase, xmlrpcClient)
	searchHandler := handlers.NewSearchHandler(searchUsecase)
	vpnStatusHandler := handlers.NewVPNStatusHandler(vpnStatusUsecase)
	disconnectHandler := handlers.NewDisconnectHandler(disconnectUsecase)
	configHandler := handlers.NewConfigHandler(configUsecase)

	// ✅ ENHANCED: Initialize cache handler
	cacheHandler := handlers.NewCacheHandler(redisClient)

	// Initialize router with all handlers
	router := httpRouter.NewRouterUpdated(
		authHandler,
		userHandler,
		groupHandler,
		bulkHandler,
		searchHandler,
		authMiddleware,
		corsMiddleware,
		vpnStatusHandler,
		disconnectHandler,
		configHandler,
		cacheHandler,
	)

	// Setup routes
	ginEngine := router.SetupRoutes()

	// ✅ NEW: Warm up cache if enabled
	if cfg.Redis.Enabled {
		go func() {
			logger.Log.Info("Starting cache warmup in background")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Warm up config cache (most important)
			if cachedConfigRepo, ok := configRepo.(*xmlrpcRepositories.CachedConfigRepository); ok {
				if err := cachedConfigRepo.WarmupCache(ctx); err != nil {
					logger.Log.WithError(err).Warn("Failed to warm up config cache")
				}
			}

			logger.Log.Info("Cache warmup completed")
		}()
	}

	// Create HTTP server
	server := &http.Server{
		Addr:    ":" + cfg.Server.Port,
		Handler: ginEngine,
		// Security timeouts
		ReadTimeout:       time.Duration(cfg.Server.Timeout) * time.Second,
		WriteTimeout:      time.Duration(cfg.Server.Timeout) * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		logger.Log.WithField("port", cfg.Server.Port).Info("Server starting")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Log.WithError(err).Fatal("Server failed to start")
		}
	}()

	logger.Log.WithField("port", cfg.Server.Port).Info("GoVPN API Enhanced server started successfully")
	if cfg.Redis.Enabled {
		logger.Log.Info("🚀 Advanced caching enabled for all APIs including filters and config")
		logger.Log.Info("📊 Cache TTL settings: Users=10m, Groups=10m, Filters=2m, Config=30m, Expirations=1m")
	}

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Log.Info("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown HTTP server
	if err := server.Shutdown(ctx); err != nil {
		logger.Log.WithError(err).Error("Server forced to shutdown")
		return
	}

	// Close Redis connection
	if err := redisClient.Close(); err != nil {
		logger.Log.WithError(err).Error("Failed to close Redis connection")
	} else {
		logger.Log.Info("Redis connection closed successfully")
	}

	logger.Log.Info("Server exited successfully")
}

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
