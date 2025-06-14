package dto

import "time"

// VPNStatusResponse - Response cho API VPN Status
type VPNStatusResponse struct {
	TotalConnectedUsers int                     `json:"total_connected_users" example:"5"`
	ConnectedUsers      []ConnectedUserResponse `json:"connected_users"`
	Timestamp           time.Time               `json:"timestamp" example:"2025-06-14T15:08:06Z"`
}

// ConnectedUserResponse - Response cho user đang kết nối
type ConnectedUserResponse struct {
	CommonName         string    `json:"common_name" example:"user123"`
	RealAddress        string    `json:"real_address" example:"203.113.45.123"`
	VirtualAddress     string    `json:"virtual_address" example:"172.27.232.15"`
	VirtualIPv6Address string    `json:"virtual_ipv6_address,omitempty" example:""`
	BytesReceived      int64     `json:"bytes_received" example:"1048576"`
	BytesSent          int64     `json:"bytes_sent" example:"2097152"`
	ConnectedSince     time.Time `json:"connected_since" example:"2025-06-14T14:30:25Z"`
	ConnectedSinceUnix int64     `json:"connected_since_unix" example:"1749910225"`
	Username           string    `json:"username" example:"user123"`
	ClientID           string    `json:"client_id" example:"5"`
	PeerID             string    `json:"peer_id" example:"12"`
	DataChannelCipher  string    `json:"data_channel_cipher" example:"AES-256-GCM"`
	Country            string    `json:"country" example:"Vietnam"`
	ConnectionDuration string    `json:"connection_duration" example:"37m41s"`
}

// GlobalStatsResponse - Response cho global stats
type GlobalStatsResponse struct {
	MaxBcastMcastQueueLength string `json:"max_bcast_mcast_queue_length" example:"0"`
	DCOEnabled               bool   `json:"dco_enabled" example:"false"`
}
