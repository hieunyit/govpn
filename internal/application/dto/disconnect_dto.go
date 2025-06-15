// internal/application/dto/disconnect_dto.go
package dto

import "time"

// BulkDisconnectUsersRequest - API request để disconnect nhiều users
type BulkDisconnectUsersRequest struct {
	Usernames []string `json:"usernames" validate:"required,min=1" example:"[\"testuser1\", \"testuser2\"]"`
	Message   string   `json:"message" validate:"max=200" example:"Maintenance disconnect"`
}

// DisconnectUserRequest - API request để disconnect một user
type DisconnectUserRequest struct {
	Message string `json:"message" validate:"max=200" example:"Session terminated by administrator"`
}

// DisconnectResponse - API response cho disconnect operations với validation info
type DisconnectResponse struct {
	Success           bool                  `json:"success" example:"true"`
	DisconnectedUsers []string              `json:"disconnected_users" example:"[\"testuser1\", \"testuser2\"]"`
	Message           string                `json:"message" example:"Users disconnected successfully"`
	Count             int                   `json:"count" example:"2"`
	TotalRequested    *int                  `json:"total_requested,omitempty" example:"3"`
	SkippedUsers      []string              `json:"skipped_users,omitempty" example:"[\"offline_user\"]"`
	ValidationErrors  []UserValidationError `json:"validation_errors,omitempty"`
	ConnectionInfo    *UserConnectionInfo   `json:"connection_info,omitempty"`
}

// UserValidationError - lỗi validation cho từng user
type UserValidationError struct {
	Username string `json:"username" example:"testuser1"`
	Error    string `json:"error" example:"User is not currently connected"`
}

// UserConnectionInfo - thông tin connection của user được disconnect
type UserConnectionInfo struct {
	Username       string    `json:"username" example:"testuser1"`
	RealAddress    string    `json:"real_address" example:"203.113.45.123"`
	VirtualAddress string    `json:"virtual_address" example:"172.27.232.15"`
	ConnectedSince time.Time `json:"connected_since" example:"2025-06-14T14:30:25Z"`
	Country        string    `json:"country" example:"Vietnam"`
}
