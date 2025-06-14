package entities

import "time"

// VPNStatus - thông tin status của VPN server
type VPNStatus struct {
	ServerName          string           `json:"server_name"`
	ServerTitle         string           `json:"server_title"`
	ServerTime          time.Time        `json:"server_time"`
	TotalConnectedUsers int              `json:"total_connected_users"`
	ConnectedUsers      []*ConnectedUser `json:"connected_users"`
	GlobalStats         *GlobalStats     `json:"global_stats"`
}

// ConnectedUser - thông tin user đang kết nối VPN
type ConnectedUser struct {
	CommonName         string    `json:"common_name"`
	RealAddress        string    `json:"real_address"`    // IP public của user
	VirtualAddress     string    `json:"virtual_address"` // IP VPN được cấp
	VirtualIPv6Address string    `json:"virtual_ipv6_address,omitempty"`
	BytesReceived      int64     `json:"bytes_received"`
	BytesSent          int64     `json:"bytes_sent"`
	ConnectedSince     time.Time `json:"connected_since"` // Thời gian bắt đầu kết nối
	ConnectedSinceUnix int64     `json:"connected_since_unix"`
	Username           string    `json:"username"`
	ClientID           string    `json:"client_id"`
	PeerID             string    `json:"peer_id"`
	DataChannelCipher  string    `json:"data_channel_cipher"`
	Country            string    `json:"country"`             // Quốc gia từ IP public
	ConnectionDuration string    `json:"connection_duration"` // Thời gian đã kết nối
}

// GlobalStats - thống kê global của VPN server
type GlobalStats struct {
	MaxBcastMcastQueueLength string `json:"max_bcast_mcast_queue_length"`
	DCOEnabled               bool   `json:"dco_enabled"`
}

// VPNStatusSummary - tóm tắt tổng quan VPN status
type VPNStatusSummary struct {
	TotalConnectedUsers int              `json:"total_connected_users"`
	ConnectedUsers      []*ConnectedUser `json:"connected_users"`
	Timestamp           time.Time        `json:"timestamp"`
}
