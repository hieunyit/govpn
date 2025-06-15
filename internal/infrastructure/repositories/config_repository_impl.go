package repositories

import (
	"context"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/repositories"
	"govpn/internal/infrastructure/xmlrpc"
	"strings"
)

type configRepositoryImpl struct {
	configClient *xmlrpc.ConfigClient
}

func NewConfigRepository(xmlrpcClient *xmlrpc.Client) repositories.ConfigRepository {
	return &configRepositoryImpl{
		configClient: xmlrpc.NewConfigClient(xmlrpcClient),
	}
}

func (r *configRepositoryImpl) GetServerInfo(ctx context.Context) (*entities.ServerInfo, error) {
	configMap, err := r.configClient.GetConfig()
	if err != nil {
		return nil, err
	}

	serverInfo := &entities.ServerInfo{
		NodeType:        r.getConfigValue(configMap, "node_type"),
		WebServerName:   r.getConfigValue(configMap, "cs.web_server_name"),
		AdminPort:       r.getConfigValue(configMap, "admin_ui.https.port"),
		AdminIPAddress:  r.getConfigValue(configMap, "admin_ui.https.ip_address"),
		ClientPort:      r.getConfigValue(configMap, "cs.https.port"),
		ClientIPAddress: r.getConfigValue(configMap, "cs.https.ip_address"),
		LicenseServer:   r.getConfigValue(configMap, "lic.server"),
		ClusterMode:     r.getConfigValue(configMap, "cluster.mode"),
		FailoverMode:    r.getConfigValue(configMap, "failover.mode"),
	}

	return serverInfo, nil
}

func (r *configRepositoryImpl) GetNetworkConfig(ctx context.Context) (*entities.NetworkConfig, error) {
	configMap, err := r.configClient.GetConfig()
	if err != nil {
		return nil, err
	}

	networkConfig := &entities.NetworkConfig{
		// Client Network Settings
		ClientNetwork:     r.getConfigValue(configMap, "vpn.daemon.0.client.network"),
		ClientNetmaskBits: r.getConfigValue(configMap, "vpn.daemon.0.client.netmask_bits"),
		GroupPool:         r.getConfigValue(configMap, "vpn.server.group_pool.0"),

		// VPN Daemon Settings
		TCPPort:  r.getConfigValue(configMap, "vpn.server.daemon.tcp.port"),
		UDPPort:  r.getConfigValue(configMap, "vpn.server.daemon.udp.port"),
		ListenIP: r.getConfigValue(configMap, "vpn.daemon.0.listen.ip_address"),
		Protocol: r.getConfigValue(configMap, "vpn.daemon.0.listen.protocol"),
		ServerIP: r.getConfigValue(configMap, "vpn.daemon.0.server.ip_address"),

		// Network Performance
		MTU:      r.getConfigValue(configMap, "vpn.general.mtu"),
		MSSSFix:  r.getConfigValue(configMap, "vpn.server.mssfix"),
		OSILayer: r.getConfigValue(configMap, "vpn.general.osi_layer"),

		// Routing Settings
		RerouteGateway: r.parseBool(r.getConfigValue(configMap, "vpn.client.routing.reroute_gw")),
		RerouteDNS:     r.parseBool(r.getConfigValue(configMap, "vpn.client.routing.reroute_dns")),
		InterClient:    r.parseBool(r.getConfigValue(configMap, "vpn.client.routing.inter_client")),
		PrivateAccess:  r.getConfigValue(configMap, "vpn.server.routing.private_access"),

		// NAT Settings
		NATEnabled:     r.parseBool(r.getConfigValue(configMap, "vpn.server.nat")),
		NATMasquerade:  r.parseBool(r.getConfigValue(configMap, "vpn.server.nat.masquerade")),
		NAT6Enabled:    r.parseBool(r.getConfigValue(configMap, "vpn.server.nat6")),
		NAT6Masquerade: r.parseBool(r.getConfigValue(configMap, "vpn.server.nat6.masquerade")),

		// Advanced Network Settings
		AllowPrivateNetsToClients:  r.parseBool(r.getConfigValue(configMap, "vpn.server.routing.allow_private_nets_to_clients")),
		AllowPrivateNets6ToClients: r.parseBool(r.getConfigValue(configMap, "vpn.server.routing6.allow_private_nets_to_clients")),
	}

	return networkConfig, nil
}

func (r *configRepositoryImpl) GetAllConfig(ctx context.Context) (map[string]string, error) {
	return r.configClient.GetConfig()
}

// Helper functions
func (r *configRepositoryImpl) getConfigValue(configMap map[string]string, key string) string {
	if value, exists := configMap[key]; exists {
		return value
	}
	return ""
}

func (r *configRepositoryImpl) parseBool(value string) bool {
	value = strings.ToLower(value)
	return value == "true" || value == "1"
}
