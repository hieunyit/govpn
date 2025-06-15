// internal/domain/entities/config.go
package entities

// ServerInfo - thông tin cơ bản của server
type ServerInfo struct {
	NodeType        string `json:"node_type"`
	WebServerName   string `json:"web_server_name"`
	AdminPort       string `json:"admin_port"`
	AdminIPAddress  string `json:"admin_ip_address"`
	ClientPort      string `json:"client_port"`
	ClientIPAddress string `json:"client_ip_address"`
	LicenseServer   string `json:"license_server"`
	ClusterMode     string `json:"cluster_mode"`
	FailoverMode    string `json:"failover_mode"`
}

// NetworkConfig - cấu hình network của VPN
type NetworkConfig struct {
	// Client Network Settings
	ClientNetwork     string `json:"client_network"`
	ClientNetmaskBits string `json:"client_netmask_bits"`
	GroupPool         string `json:"group_pool"`

	// VPN Daemon Settings
	TCPPort  string `json:"tcp_port"`
	UDPPort  string `json:"udp_port"`
	ListenIP string `json:"listen_ip"`
	Protocol string `json:"protocol"`
	ServerIP string `json:"server_ip"`

	// Network Performance
	MTU      string `json:"mtu"`
	MSSSFix  string `json:"mss_fix"`
	OSILayer string `json:"osi_layer"`

	// Routing Settings
	RerouteGateway bool   `json:"reroute_gateway"`
	RerouteDNS     bool   `json:"reroute_dns"`
	InterClient    bool   `json:"inter_client"`
	PrivateAccess  string `json:"private_access"`

	// NAT Settings
	NATEnabled     bool `json:"nat_enabled"`
	NATMasquerade  bool `json:"nat_masquerade"`
	NAT6Enabled    bool `json:"nat6_enabled"`
	NAT6Masquerade bool `json:"nat6_masquerade"`

	// Advanced Network Settings
	AllowPrivateNetsToClients  bool `json:"allow_private_nets_to_clients"`
	AllowPrivateNets6ToClients bool `json:"allow_private_nets6_to_clients"`
}
