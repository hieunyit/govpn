package handlers

import (
	"govpn/internal/application/dto"
	"govpn/internal/domain/usecases"
	"govpn/pkg/errors"
	"govpn/pkg/logger"
	"net/http"

	"github.com/gin-gonic/gin"
)

type ConfigHandler struct {
	configUsecase usecases.ConfigUsecase
}

func NewConfigHandler(configUsecase usecases.ConfigUsecase) *ConfigHandler {
	return &ConfigHandler{
		configUsecase: configUsecase,
	}
}

// GetServerInfo godoc
// @Summary Get server information
// @Description Get basic server information including node type, ports, and cluster configuration
// @Tags Configuration
// @Security BearerAuth
// @Produce json
// @Success 200 {object} dto.SuccessResponse{data=dto.ServerInfoResponse} "Server information retrieved successfully"
// @Failure 401 {object} dto.ErrorResponse "Unauthorized - invalid or missing authentication"
// @Failure 500 {object} dto.ErrorResponse "Internal server error - failed to retrieve server info"
// @Router /api/openvpn/config/server/info [get]
func (h *ConfigHandler) GetServerInfo(c *gin.Context) {
	logger.Log.Info("Getting server information")

	// Business logic thông qua usecase
	result, err := h.configUsecase.GetServerInfo(c.Request.Context())
	if err != nil {
		logger.Log.WithError(err).Error("Failed to get server info from usecase")
		RespondWithError(c, errors.InternalServerError("Failed to retrieve server information", err))
		return
	}

	// Convert usecase result to DTO
	response := dto.ServerInfoResponse{
		NodeType:        result.ServerInfo.NodeType,
		WebServerName:   result.ServerInfo.WebServerName,
		AdminPort:       result.ServerInfo.AdminPort,
		AdminIPAddress:  result.ServerInfo.AdminIPAddress,
		ClientPort:      result.ServerInfo.ClientPort,
		ClientIPAddress: result.ServerInfo.ClientIPAddress,
		LicenseServer:   result.ServerInfo.LicenseServer,
		ClusterMode:     result.ServerInfo.ClusterMode,
		FailoverMode:    result.ServerInfo.FailoverMode,
		Status:          result.Status,
		Message:         result.Message,
	}

	logger.Log.WithField("node_type", result.ServerInfo.NodeType).
		WithField("status", result.Status).
		Info("Server information retrieved successfully")

	RespondWithSuccess(c, http.StatusOK, response)
}

// GetNetworkConfig godoc
// @Summary Get network configuration
// @Description Get comprehensive network configuration including client networks, VPN daemon settings, routing, and NAT configuration
// @Tags Configuration
// @Security BearerAuth
// @Produce json
// @Success 200 {object} dto.SuccessResponse{data=dto.NetworkConfigResponse} "Network configuration retrieved successfully"
// @Failure 401 {object} dto.ErrorResponse "Unauthorized - invalid or missing authentication"
// @Failure 500 {object} dto.ErrorResponse "Internal server error - failed to retrieve network config"
// @Router /api/openvpn/config/network [get]
func (h *ConfigHandler) GetNetworkConfig(c *gin.Context) {
	logger.Log.Info("Getting network configuration")

	// Business logic thông qua usecase
	result, err := h.configUsecase.GetNetworkConfig(c.Request.Context())
	if err != nil {
		logger.Log.WithError(err).Error("Failed to get network config from usecase")
		RespondWithError(c, errors.InternalServerError("Failed to retrieve network configuration", err))
		return
	}

	// Convert usecase result to DTO
	response := dto.NetworkConfigResponse{
		// Client Network Settings
		ClientNetwork:     result.NetworkConfig.ClientNetwork,
		ClientNetmaskBits: result.NetworkConfig.ClientNetmaskBits,
		GroupPool:         result.NetworkConfig.GroupPool,

		// VPN Daemon Settings
		TCPPort:  result.NetworkConfig.TCPPort,
		UDPPort:  result.NetworkConfig.UDPPort,
		ListenIP: result.NetworkConfig.ListenIP,
		Protocol: result.NetworkConfig.Protocol,
		ServerIP: result.NetworkConfig.ServerIP,

		// Network Performance
		MTU:      result.NetworkConfig.MTU,
		MSSSFix:  result.NetworkConfig.MSSSFix,
		OSILayer: result.NetworkConfig.OSILayer,

		// Routing Settings
		RerouteGateway: result.NetworkConfig.RerouteGateway,
		RerouteDNS:     result.NetworkConfig.RerouteDNS,
		InterClient:    result.NetworkConfig.InterClient,
		PrivateAccess:  result.NetworkConfig.PrivateAccess,

		// NAT Settings
		NATEnabled:     result.NetworkConfig.NATEnabled,
		NATMasquerade:  result.NetworkConfig.NATMasquerade,
		NAT6Enabled:    result.NetworkConfig.NAT6Enabled,
		NAT6Masquerade: result.NetworkConfig.NAT6Masquerade,

		// Advanced Network Settings
		AllowPrivateNetsToClients:  result.NetworkConfig.AllowPrivateNetsToClients,
		AllowPrivateNets6ToClients: result.NetworkConfig.AllowPrivateNets6ToClients,

		// Status
		Status:  result.Status,
		Message: result.Message,
	}

	logger.Log.WithField("client_network", result.NetworkConfig.ClientNetwork).
		WithField("tcp_port", result.NetworkConfig.TCPPort).
		WithField("udp_port", result.NetworkConfig.UDPPort).
		WithField("status", result.Status).
		Info("Network configuration retrieved successfully")

	RespondWithSuccess(c, http.StatusOK, response)
}
