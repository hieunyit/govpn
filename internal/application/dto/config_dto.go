package dto

// ServerInfoResponse - API response cho server information
type ServerInfoResponse struct {
	NodeType        string `json:"node_type" example:"PRIMARY"`
	WebServerName   string `json:"web_server_name" example:"OpenVPN-AS"`
	AdminPort       string `json:"admin_port" example:"943"`
	AdminIPAddress  string `json:"admin_ip_address" example:"all"`
	ClientPort      string `json:"client_port" example:"943"`
	ClientIPAddress string `json:"client_ip_address" example:"all"`
	LicenseServer   string `json:"license_server" example:"licensing.openvpn.net:443"`
	ClusterMode     string `json:"cluster_mode" example:"False"`
	FailoverMode    string `json:"failover_mode" example:"none"`
	Status          string `json:"status" example:"healthy"`
	Message         string `json:"message" example:"Server info retrieved successfully"`
}

// NetworkConfigResponse - API response cho network configuration
type NetworkConfigResponse struct {
	// Client Network Settings
	ClientNetwork     string `json:"client_network" example:"172.27.224.0"`
	ClientNetmaskBits string `json:"client_netmask_bits" example:"20"`
	GroupPool         string `json:"group_pool" example:"172.27.240.0/20"`

	// VPN Daemon Settings
	TCPPort  string `json:"tcp_port" example:"443"`
	UDPPort  string `json:"udp_port" example:"1194"`
	ListenIP string `json:"listen_ip" example:"all"`
	Protocol string `json:"protocol" example:"tcp"`
	ServerIP string `json:"server_ip" example:"all"`

	// Network Performance
	MTU      string `json:"mtu" example:"1420"`
	MSSSFix  string `json:"mss_fix" example:"1350"`
	OSILayer string `json:"osi_layer" example:"3"`

	// Routing Settings
	RerouteGateway bool   `json:"reroute_gateway" example:"true"`
	RerouteDNS     bool   `json:"reroute_dns" example:"true"`
	InterClient    bool   `json:"inter_client" example:"false"`
	PrivateAccess  string `json:"private_access" example:"no"`

	// NAT Settings
	NATEnabled     bool `json:"nat_enabled" example:"true"`
	NATMasquerade  bool `json:"nat_masquerade" example:"false"`
	NAT6Enabled    bool `json:"nat6_enabled" example:"true"`
	NAT6Masquerade bool `json:"nat6_masquerade" example:"false"`

	// Advanced Network Settings
	AllowPrivateNetsToClients  bool `json:"allow_private_nets_to_clients" example:"true"`
	AllowPrivateNets6ToClients bool `json:"allow_private_nets6_to_clients" example:"true"`

	// Status
	Status  string `json:"status" example:"optimal"`
	Message string `json:"message" example:"Network config retrieved successfully"`
}
