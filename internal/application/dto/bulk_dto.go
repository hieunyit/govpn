package dto

import (
	"mime/multipart"
)

// =================== BULK USER OPERATIONS ===================

// BulkCreateUsersRequest for creating multiple users at once
type BulkCreateUsersRequest struct {
	Users []CreateUserRequest `json:"users" validate:"required,min=1,max=100,dive"`
}

// BulkCreateUsersResponse with detailed results for each user
type BulkCreateUsersResponse struct {
	Total   int                       `json:"total" example:"10"`
	Success int                       `json:"success" example:"8"`
	Failed  int                       `json:"failed" example:"2"`
	Results []BulkUserOperationResult `json:"results"`
}

// BulkUserActionsRequest for bulk enable/disable operations
type BulkUserActionsRequest struct {
	Usernames []string `json:"usernames" validate:"required,min=1,max=100,dive,min=3,max=30"`
	Action    string   `json:"action" validate:"required,oneof=enable disable reset-otp"`
}

// BulkUserExtendRequest for bulk expiration extension
type BulkUserExtendRequest struct {
	Usernames     []string `json:"usernames" validate:"required,min=1,max=100,dive,min=3,max=30"`
	NewExpiration string   `json:"newExpiration" validate:"required,date"`
}

// BulkUserOperationResult represents result for individual user operation
type BulkUserOperationResult struct {
	Username string `json:"username" example:"testuser"`
	Success  bool   `json:"success" example:"true"`
	Message  string `json:"message" example:"User created successfully"`
	Error    string `json:"error,omitempty" example:""`
}

// BulkActionResponse for bulk operations response
type BulkActionResponse struct {
	Total   int                       `json:"total" example:"10"`
	Success int                       `json:"success" example:"8"`
	Failed  int                       `json:"failed" example:"2"`
	Results []BulkUserOperationResult `json:"results"`
}

// =================== BULK GROUP OPERATIONS ===================

// BulkCreateGroupsRequest for creating multiple groups at once
type BulkCreateGroupsRequest struct {
	Groups []CreateGroupRequest `json:"groups" validate:"required,min=1,max=50,dive"`
}

// BulkCreateGroupsResponse with detailed results for each group
type BulkCreateGroupsResponse struct {
	Total   int                        `json:"total" example:"5"`
	Success int                        `json:"success" example:"4"`
	Failed  int                        `json:"failed" example:"1"`
	Results []BulkGroupOperationResult `json:"results"`
}

// BulkGroupActionsRequest for bulk group enable/disable operations
type BulkGroupActionsRequest struct {
	GroupNames []string `json:"groupNames" validate:"required,min=1,max=50,dive,min=3,max=50"`
	Action     string   `json:"action" validate:"required,oneof=enable disable"`
}

// BulkGroupOperationResult represents result for individual group operation
type BulkGroupOperationResult struct {
	GroupName string `json:"groupName" example:"TEST_GROUP"`
	Success   bool   `json:"success" example:"true"`
	Message   string `json:"message" example:"Group created successfully"`
	Error     string `json:"error,omitempty" example:""`
}

// BulkGroupActionResponse for bulk group operations response
type BulkGroupActionResponse struct {
	Total   int                        `json:"total" example:"5"`
	Success int                        `json:"success" example:"4"`
	Failed  int                        `json:"failed" example:"1"`
	Results []BulkGroupOperationResult `json:"results"`
}

// =================== FILE IMPORT OPERATIONS ===================

// ImportUsersRequest for importing users from file
type ImportUsersRequest struct {
	File     *multipart.FileHeader `form:"file" binding:"required"`
	DryRun   bool                  `form:"dryRun" example:"false"`
	Format   string                `form:"format" validate:"oneof=csv json xlsx" example:"csv"`
	Override bool                  `form:"override" example:"false"` // Override existing users
}

// ImportGroupsRequest for importing groups from file
type ImportGroupsRequest struct {
	File     *multipart.FileHeader `form:"file" binding:"required"`
	DryRun   bool                  `form:"dryRun" example:"false"`
	Format   string                `form:"format" validate:"oneof=csv json xlsx" example:"csv"`
	Override bool                  `form:"override" example:"false"`
}

// ImportValidationError represents validation error during import
type ImportValidationError struct {
	Row     int    `json:"row" example:"3"`
	Field   string `json:"field" example:"email"`
	Value   string `json:"value" example:"invalid-email"`
	Message string `json:"message" example:"Invalid email format"`
}

// ImportResponse for file import operations
type ImportResponse struct {
	Total            int                     `json:"total" example:"100"`
	ValidRecords     int                     `json:"validRecords" example:"95"`
	InvalidRecords   int                     `json:"invalidRecords" example:"5"`
	ProcessedRecords int                     `json:"processedRecords" example:"95"`
	SuccessCount     int                     `json:"successCount" example:"90"`
	FailureCount     int                     `json:"failureCount" example:"5"`
	DryRun           bool                    `json:"dryRun" example:"false"`
	ValidationErrors []ImportValidationError `json:"validationErrors,omitempty"`
	Results          interface{}             `json:"results,omitempty"` // BulkCreateUsersResponse or BulkCreateGroupsResponse
}

// =================== CSV TEMPLATES ===================

// UserCSVRecord represents a user record in CSV format
type UserCSVRecord struct {
	Username       string `csv:"username" example:"testuser"`
	Email          string `csv:"email" example:"test@example.com"`
	Password       string `csv:"password,omitempty" example:"SecurePass123!"`
	AuthMethod     string `csv:"auth_method" example:"local"`
	GroupName      string `csv:"group_name,omitempty" example:"TEST_GROUP"`
	UserExpiration string `csv:"user_expiration" example:"31/12/2024"`
	MacAddresses   string `csv:"mac_addresses" example:"AA:BB:CC:DD:EE:FF,11:22:33:44:55:66"`
	AccessControl  string `csv:"access_control,omitempty" example:"192.168.1.0/24,10.0.0.0/8"`
	IPAssignMode   string `csv:"ip_assign_mode" example:"dynamic"`
	IPAddress      string `csv:"ip_address,omitempty" example:"10.0.0.10"`
}

// GroupCSVRecord represents a group record in CSV format - UPDATED with new fields
type GroupCSVRecord struct {
	GroupName     string `csv:"group_name" example:"TEST_GROUP"`
	AuthMethod    string `csv:"auth_method" example:"local"`
	MFA           string `csv:"mfa" example:"true"`
	Role          string `csv:"role" example:"User"`
	AccessControl string `csv:"access_control,omitempty" example:"192.168.1.0/24,10.0.0.0/8"`
	GroupSubnet   string `csv:"group_subnet,omitempty" example:"10.8.0.0/24"`
	GroupRange    string `csv:"group_range,omitempty" example:"10.8.0.100-10.8.0.200"`
}

// =================== VALIDATION MESSAGES ===================

func (r BulkCreateUsersRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"Users.required": "At least one user is required",
		"Users.min":      "At least one user is required",
		"Users.max":      "Maximum 100 users allowed per batch",
	}
}

func (r BulkUserActionsRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"Usernames.required": "At least one username is required",
		"Usernames.min":      "At least one username is required",
		"Usernames.max":      "Maximum 100 usernames allowed per batch",
		"Action.required":    "Action is required",
		"Action.oneof":       "Action must be one of: enable, disable, reset-otp",
	}
}

func (r BulkUserExtendRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"Usernames.required":     "At least one username is required",
		"Usernames.min":          "At least one username is required",
		"Usernames.max":          "Maximum 100 usernames allowed per batch",
		"NewExpiration.required": "New expiration date is required",
		"NewExpiration.date":     "New expiration must be a future date in format DD/MM/YYYY",
	}
}

func (r BulkCreateGroupsRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"Groups.required": "At least one group is required",
		"Groups.min":      "At least one group is required",
		"Groups.max":      "Maximum 50 groups allowed per batch",
	}
}

func (r BulkGroupActionsRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"GroupNames.required": "At least one group name is required",
		"GroupNames.min":      "At least one group name is required",
		"GroupNames.max":      "Maximum 50 group names allowed per batch",
		"Action.required":     "Action is required",
		"Action.oneof":        "Action must be one of: enable, disable",
	}
}

func (r ImportUsersRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"File.required": "File is required",
		"Format.oneof":  "Format must be one of: csv, json, xlsx",
	}
}

func (r ImportGroupsRequest) GetValidationErrors() map[string]string {
	return map[string]string{
		"File.required": "File is required",
		"Format.oneof":  "Format must be one of: csv, json, xlsx",
	}
}
