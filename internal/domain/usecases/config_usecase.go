package usecases

import (
	"context"
	"fmt"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/repositories"
	"govpn/pkg/logger"
)

type ConfigUsecase interface {
	GetServerInfo(ctx context.Context) (*ServerInfoResult, error)
	GetNetworkConfig(ctx context.Context) (*NetworkConfigResult, error)
}

type configUsecase struct {
	configRepo repositories.ConfigRepository
}

func NewConfigUsecase(configRepo repositories.ConfigRepository) ConfigUsecase {
	return &configUsecase{
		configRepo: configRepo,
	}
}

// ServerInfoResult - kết quả business logic cho server info
type ServerInfoResult struct {
	ServerInfo *entities.ServerInfo `json:"server_info"`
	Status     string               `json:"status"`
	Message    string               `json:"message"`
}

// NetworkConfigResult - kết quả business logic cho network config
type NetworkConfigResult struct {
	NetworkConfig *entities.NetworkConfig `json:"network_config"`
	Status        string                  `json:"status"`
	Message       string                  `json:"message"`
}

// GetServerInfo - business logic để lấy server information
func (u *configUsecase) GetServerInfo(ctx context.Context) (*ServerInfoResult, error) {
	logger.Log.Info("Getting server info from usecase")

	// Business Rule: Get server info from repository
	serverInfo, err := u.configRepo.GetServerInfo(ctx)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to get server info from repository")
		return &ServerInfoResult{
			Status:  "error",
			Message: "Failed to retrieve server information",
		}, fmt.Errorf("failed to get server info: %w", err)
	}

	// Business Rule: Validate và enrich server info
	status := u.validateServerInfo(serverInfo)

	result := &ServerInfoResult{
		ServerInfo: serverInfo,
		Status:     status,
		Message:    fmt.Sprintf("Server info retrieved successfully - Node: %s", serverInfo.NodeType),
	}

	logger.Log.WithField("node_type", serverInfo.NodeType).
		WithField("admin_port", serverInfo.AdminPort).
		Info("Server info retrieved successfully")

	return result, nil
}

// GetNetworkConfig - business logic để lấy network configuration
func (u *configUsecase) GetNetworkConfig(ctx context.Context) (*NetworkConfigResult, error) {
	logger.Log.Info("Getting network config from usecase")

	// Business Rule: Get network config from repository
	networkConfig, err := u.configRepo.GetNetworkConfig(ctx)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to get network config from repository")
		return &NetworkConfigResult{
			Status:  "error",
			Message: "Failed to retrieve network configuration",
		}, fmt.Errorf("failed to get network config: %w", err)
	}

	// Business Rule: Validate và enrich network config
	status := u.validateNetworkConfig(networkConfig)

	result := &NetworkConfigResult{
		NetworkConfig: networkConfig,
		Status:        status,
		Message:       fmt.Sprintf("Network config retrieved successfully - Client Network: %s", networkConfig.ClientNetwork),
	}

	logger.Log.WithField("client_network", networkConfig.ClientNetwork).
		WithField("tcp_port", networkConfig.TCPPort).
		WithField("udp_port", networkConfig.UDPPort).
		Info("Network config retrieved successfully")

	return result, nil
}

// validateServerInfo - business rule để validate server info
func (u *configUsecase) validateServerInfo(serverInfo *entities.ServerInfo) string {
	// Business logic: Check server health based on configuration
	if serverInfo.NodeType == "" {
		return "warning"
	}

	if serverInfo.AdminPort == "" || serverInfo.ClientPort == "" {
		return "warning"
	}

	if serverInfo.NodeType == "PRIMARY" && serverInfo.ClusterMode == "True" {
		return "clustered"
	}

	return "healthy"
}

// validateNetworkConfig - business rule để validate network config
func (u *configUsecase) validateNetworkConfig(networkConfig *entities.NetworkConfig) string {
	// Business logic: Check network configuration health
	if networkConfig.ClientNetwork == "" {
		return "error"
	}

	if networkConfig.TCPPort == "" && networkConfig.UDPPort == "" {
		return "error"
	}

	// Check if both TCP and UDP are configured
	if networkConfig.TCPPort != "" && networkConfig.UDPPort != "" {
		return "optimal"
	}

	return "healthy"
}
