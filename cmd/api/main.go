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
	presentation "govpn/internal/presentation/http"
	"govpn/pkg/config"
	"govpn/pkg/logger"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	// Initialize logger
	logger.Init(cfg.Logger)

	// Initialize infrastructure
	xmlrpcClient := xmlrpc.NewClient(cfg.OpenVPN)
	ldapClient := ldap.NewClient(cfg.LDAP)

	// Initialize repositories
	userRepo := repositories.NewUserRepository(xmlrpcClient)
	groupRepo := repositories.NewGroupRepository(xmlrpcClient)

	// Initialize use cases
	authUsecase := usecases.NewAuthUsecase(userRepo, ldapClient, cfg.JWT)
	userUsecase := usecases.NewUserUsecase(userRepo, groupRepo, ldapClient)
	groupUsecase := usecases.NewGroupUsecase(groupRepo)

	// Initialize middleware
	authMiddleware := middleware.NewAuthMiddleware(cfg.JWT.Secret)
	corsMiddleware := middleware.NewCorsMiddleware()

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authUsecase)
	userHandler := handlers.NewUserHandler(userUsecase, xmlrpcClient)
	groupHandler := handlers.NewGroupHandler(groupUsecase, xmlrpcClient)

	// Initialize router
	router := presentation.NewRouter(
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
