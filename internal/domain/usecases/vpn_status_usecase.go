package usecases

import (
	"context"
	"fmt"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/repositories"
	"govpn/pkg/logger"
	"time"
)

type VPNStatusUsecase interface {
	GetVPNStatus(ctx context.Context) (*VPNStatusResult, error)
}

type vpnStatusUsecase struct {
	vpnStatusRepo repositories.VPNStatusRepository
}

func NewVPNStatusUsecase(vpnStatusRepo repositories.VPNStatusRepository) VPNStatusUsecase {
	return &vpnStatusUsecase{
		vpnStatusRepo: vpnStatusRepo,
	}
}

// VPNStatusResult - kết quả business logic đơn giản
type VPNStatusResult struct {
	TotalConnectedUsers int                       `json:"total_connected_users"`
	ConnectedUsers      []*entities.ConnectedUser `json:"connected_users"`
	Timestamp           time.Time                 `json:"timestamp"`
}

// GetVPNStatus - business logic đơn giản cho VPN status
func (u *vpnStatusUsecase) GetVPNStatus(ctx context.Context) (*VPNStatusResult, error) {
	logger.Log.Info("Processing VPN status request in usecase")

	// Business Rule: Get VPN status from repository
	vpnStatus, err := u.vpnStatusRepo.GetVPNStatus(ctx)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to get VPN status from repository")
		return nil, fmt.Errorf("failed to get VPN status: %w", err)
	}

	// Business Rule: Process connected users (đơn giản)
	processedUsers := make([]*entities.ConnectedUser, len(vpnStatus.ConnectedUsers))
	for i, user := range vpnStatus.ConnectedUsers {
		// Business logic đơn giản: ensure connection duration is calculated
		if user.ConnectionDuration == "" && !user.ConnectedSince.IsZero() {
			duration := time.Since(user.ConnectedSince)
			user.ConnectionDuration = u.formatDuration(duration)
		}

		// Ensure country field is not empty
		if user.Country == "" {
			user.Country = "Unknown"
		}

		processedUsers[i] = user
	}

	// Return processed result
	result := &VPNStatusResult{
		TotalConnectedUsers: len(processedUsers),
		ConnectedUsers:      processedUsers,
		Timestamp:           time.Now(),
	}

	logger.Log.WithField("connected_users", len(processedUsers)).
		Info("VPN status processed successfully in usecase")

	return result, nil
}

// formatDuration - helper để format duration
func (u *vpnStatusUsecase) formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	} else {
		return fmt.Sprintf("%ds", seconds)
	}
}
