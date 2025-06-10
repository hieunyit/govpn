// @title           GoVPN API
// @version         1.0
// @description     OpenVPN Access Server Management API with RSA256 JWT
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
	"govpn/pkg/logger"

	_ "govpn/docs" // Import generated docs
)

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

	// Log JWT configuration mode
	if cfg.JWT.UseRSA {
		logger.Log.Info("Starting GoVPN API with RSA256 JWT authentication")
	} else {
		logger.Log.Warn("Starting GoVPN API with legacy HMAC256 JWT authentication")
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

	// Initialize use cases
	authUsecase := usecases.NewAuthUsecase(userRepo, ldapClient, cfg.JWT)
	userUsecase := usecases.NewUserUsecase(userRepo, groupRepo, ldapClient)
	groupUsecase := usecases.NewGroupUsecase(groupRepo)

	// Initialize middleware with full JWT config
	authMiddleware := middleware.NewAuthMiddleware(cfg.JWT)
	corsMiddleware := middleware.NewCorsMiddleware()

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authUsecase)
	userHandler := handlers.NewUserHandler(userUsecase, xmlrpcClient)
	groupHandler := handlers.NewGroupHandler(groupUsecase, xmlrpcClient)

	// Initialize router
	router := httpRouter.NewRouter(
		authHandler,
		userHandler,
		groupHandler,
		authMiddleware,
		corsMiddleware,
	)

	// Start server
	server := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      router.SetupRoutes(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		logger.Log.Info("Server starting on port " + cfg.Server.Port)
		logger.Log.Info("Swagger UI available at: http://localhost:" + cfg.Server.Port + "/swagger/index.html")

		if cfg.JWT.UseRSA {
			logger.Log.Info("Using RSA256 JWT tokens for enhanced security")
		} else {
			logger.Log.Warn("Using HMAC256 JWT tokens - consider upgrading to RSA256 for production")
		}

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

	logger.Log.Info("Server exited")
}
