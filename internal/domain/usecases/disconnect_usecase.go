// internal/domain/usecases/disconnect_usecase.go
package usecases

import (
	"context"
	"fmt"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/repositories"
	"govpn/pkg/logger"
	"strings"
)

type DisconnectUsecase interface {
	DisconnectUser(ctx context.Context, username, message string) (*DisconnectResult, error)
	BulkDisconnectUsers(ctx context.Context, usernames []string, message string) (*BulkDisconnectResult, error)
}

type disconnectUsecase struct {
	userRepo       repositories.UserRepository
	disconnectRepo repositories.DisconnectRepository
	vpnStatusRepo  repositories.VPNStatusRepository
}

func NewDisconnectUsecase(
	userRepo repositories.UserRepository,
	disconnectRepo repositories.DisconnectRepository,
	vpnStatusRepo repositories.VPNStatusRepository,
) DisconnectUsecase {
	return &disconnectUsecase{
		userRepo:       userRepo,
		disconnectRepo: disconnectRepo,
		vpnStatusRepo:  vpnStatusRepo,
	}
}

// DisconnectResult - kết quả disconnect single user
type DisconnectResult struct {
	Success        bool                    `json:"success"`
	Username       string                  `json:"username"`
	Message        string                  `json:"message"`
	ConnectionInfo *entities.ConnectedUser `json:"connection_info,omitempty"`
	Error          string                  `json:"error,omitempty"`
}

// BulkDisconnectResult - kết quả bulk disconnect
type BulkDisconnectResult struct {
	Success           bool                  `json:"success"`
	TotalRequested    int                   `json:"total_requested"`
	DisconnectedUsers []string              `json:"disconnected_users"`
	SkippedUsers      []string              `json:"skipped_users"`
	ValidationErrors  []UserValidationError `json:"validation_errors"`
	Message           string                `json:"message"`
}

// UserValidationError - lỗi validation cho từng user
type UserValidationError struct {
	Username string `json:"username"`
	Error    string `json:"error"`
}

// DisconnectUser - disconnect một user với business logic validation
func (u *disconnectUsecase) DisconnectUser(ctx context.Context, username, message string) (*DisconnectResult, error) {
	logger.Log.WithField("username", username).Info("Starting disconnect user process")

	// Business Rule 1: Check if user exists in system
	user, err := u.userRepo.GetByUsername(ctx, username)
	if err != nil {
		logger.Log.WithError(err).WithField("username", username).Error("User not found in system")
		return &DisconnectResult{
			Success:  false,
			Username: username,
			Error:    "User not found in system",
		}, fmt.Errorf("user not found: %w", err)
	}

	logger.Log.WithField("username", username).WithField("auth_method", user.AuthMethod).Info("User found in system")

	// Business Rule 2: Check if user is currently connected to VPN
	connectedUser, isConnected, err := u.vpnStatusRepo.IsUserConnected(ctx, username)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to check user connection status")
		return &DisconnectResult{
			Success:  false,
			Username: username,
			Error:    "Failed to check connection status",
		}, fmt.Errorf("failed to check connection: %w", err)
	}

	if !isConnected {
		logger.Log.WithField("username", username).Warn("User is not currently connected")
		return &DisconnectResult{
			Success:  false,
			Username: username,
			Error:    "User is not currently connected to VPN",
		}, fmt.Errorf("user not connected")
	}

	logger.Log.WithField("username", username).
		WithField("real_address", connectedUser.RealAddress).
		WithField("virtual_address", connectedUser.VirtualAddress).
		Info("User is connected, proceeding with disconnect")

	// Business Rule 3: Execute disconnect via infrastructure
	if err := u.disconnectRepo.DisconnectUser(ctx, username, message); err != nil {
		logger.Log.WithError(err).Error("Failed to disconnect user via infrastructure")
		return &DisconnectResult{
			Success:  false,
			Username: username,
			Error:    "Failed to execute disconnect",
		}, fmt.Errorf("disconnect failed: %w", err)
	}

	// Success result
	result := &DisconnectResult{
		Success:        true,
		Username:       username,
		Message:        "User disconnected successfully",
		ConnectionInfo: connectedUser,
	}

	logger.Log.WithField("username", username).Info("User disconnected successfully")
	return result, nil
}

// BulkDisconnectUsers - disconnect multiple users với business logic
func (u *disconnectUsecase) BulkDisconnectUsers(ctx context.Context, usernames []string, message string) (*BulkDisconnectResult, error) {
	logger.Log.WithField("usernames", usernames).WithField("count", len(usernames)).Info("Starting bulk disconnect process")

	result := &BulkDisconnectResult{
		TotalRequested:    len(usernames),
		DisconnectedUsers: make([]string, 0),
		SkippedUsers:      make([]string, 0),
		ValidationErrors:  make([]UserValidationError, 0),
	}

	// Business Rule 1: Get all connected users for batch validation
	connectedUsers, err := u.vpnStatusRepo.GetConnectedUsers(ctx)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to get connected users for bulk validation")
		return &BulkDisconnectResult{
			Success:        false,
			TotalRequested: len(usernames),
			Message:        "Failed to check connection status",
		}, fmt.Errorf("failed to get connected users: %w", err)
	}

	// Create map for fast lookup
	connectedUserMap := make(map[string]*entities.ConnectedUser)
	for _, user := range connectedUsers {
		connectedUserMap[strings.ToLower(user.Username)] = user
	}

	// Business Rule 2: Validate each user
	validUsers := make([]string, 0)
	for _, username := range usernames {
		// Check if user exists in system
		_, err := u.userRepo.GetByUsername(ctx, username)
		if err != nil {
			result.SkippedUsers = append(result.SkippedUsers, username)
			result.ValidationErrors = append(result.ValidationErrors, UserValidationError{
				Username: username,
				Error:    "User not found in system",
			})
			logger.Log.WithField("username", username).Debug("User not found in system, skipping")
			continue
		}

		// Check if user is connected
		if _, isConnected := connectedUserMap[strings.ToLower(username)]; !isConnected {
			result.SkippedUsers = append(result.SkippedUsers, username)
			result.ValidationErrors = append(result.ValidationErrors, UserValidationError{
				Username: username,
				Error:    "User is not currently connected to VPN",
			})
			logger.Log.WithField("username", username).Debug("User not connected, skipping")
			continue
		}

		// User is valid for disconnect
		validUsers = append(validUsers, username)
		logger.Log.WithField("username", username).Debug("User validated for disconnect")
	}

	if len(validUsers) == 0 {
		result.Success = false
		result.Message = "No valid users found for disconnect"
		logger.Log.Warn("No valid users found for bulk disconnect")
		return result, fmt.Errorf("no valid users to disconnect")
	}

	// Business Rule 3: Execute bulk disconnect for valid users
	if err := u.disconnectRepo.DisconnectUsers(ctx, validUsers, message); err != nil {
		logger.Log.WithError(err).Error("Failed to execute bulk disconnect")
		result.Success = false
		result.Message = "Failed to execute bulk disconnect"
		return result, fmt.Errorf("bulk disconnect failed: %w", err)
	}

	// Success result
	result.Success = true
	result.DisconnectedUsers = validUsers
	result.Message = fmt.Sprintf("Successfully disconnected %d out of %d users", len(validUsers), len(usernames))

	logger.Log.WithField("disconnected_count", len(validUsers)).
		WithField("skipped_count", len(result.SkippedUsers)).
		WithField("total_requested", len(usernames)).
		Info("Bulk disconnect completed successfully")

	return result, nil
}
