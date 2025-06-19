package usecases

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"govpn/internal/application/dto"
	"govpn/internal/domain/entities"
	"govpn/internal/domain/repositories"
	"govpn/internal/infrastructure/ldap"
	"govpn/pkg/errors"
	"govpn/pkg/logger"
	"govpn/pkg/validator"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tealeg/xlsx/v3"
)

type bulkUsecaseImpl struct {
	userRepo         repositories.UserRepository
	groupRepo        repositories.GroupRepository
	ldapClient       *ldap.Client
	mu               sync.RWMutex                       // For thread-safe operations
	operationStatus  map[string]*BulkOperationStatus    // Track operation status
	operationHistory map[string][]*BulkOperationHistory // Track operation history
}

// BulkOperationStatus represents status of ongoing operations
type BulkOperationStatus struct {
	ID         string      `json:"id"`
	EntityType string      `json:"entityType"`
	Operation  string      `json:"operation"`
	Status     string      `json:"status"` // pending, running, completed, failed
	Total      int         `json:"total"`
	Processed  int         `json:"processed"`
	Success    int         `json:"success"`
	Failed     int         `json:"failed"`
	StartTime  time.Time   `json:"startTime"`
	EndTime    *time.Time  `json:"endTime,omitempty"`
	Error      string      `json:"error,omitempty"`
	Results    interface{} `json:"results,omitempty"`
}

// BulkOperationHistory represents completed operations
type BulkOperationHistory struct {
	ID         string      `json:"id"`
	EntityType string      `json:"entityType"`
	Operation  string      `json:"operation"`
	Status     string      `json:"status"`
	Total      int         `json:"total"`
	Success    int         `json:"success"`
	Failed     int         `json:"failed"`
	Timestamp  time.Time   `json:"timestamp"`
	Duration   string      `json:"duration"`
	Results    interface{} `json:"results,omitempty"`
}

func NewBulkUsecase(userRepo repositories.UserRepository, groupRepo repositories.GroupRepository, ldapClient *ldap.Client) BulkUsecase {
	return &bulkUsecaseImpl{
		userRepo:         userRepo,
		groupRepo:        groupRepo,
		ldapClient:       ldapClient,
		operationStatus:  make(map[string]*BulkOperationStatus),
		operationHistory: make(map[string][]*BulkOperationHistory),
	}
}

// =================== BULK USER OPERATIONS ===================

func (u *bulkUsecaseImpl) BulkCreateUsers(ctx context.Context, req *dto.BulkCreateUsersRequest) (*dto.BulkCreateUsersResponse, error) {
	operationId := uuid.New().String()
	logger.Log.WithField("operationId", operationId).WithField("userCount", len(req.Users)).Info("Starting bulk user creation")

	// Initialize operation status
	status := &BulkOperationStatus{
		ID:         operationId,
		EntityType: "users",
		Operation:  "bulk_create",
		Status:     "running",
		Total:      len(req.Users),
		StartTime:  time.Now(),
	}
	u.mu.Lock()
	u.operationStatus[operationId] = status
	u.mu.Unlock()

	response := &dto.BulkCreateUsersResponse{
		Total:   len(req.Users),
		Success: 0,
		Failed:  0,
		Results: make([]dto.BulkUserOperationResult, 0, len(req.Users)),
	}

	// Process users concurrently with worker pool
	const maxWorkers = 5
	userChan := make(chan dto.CreateUserRequest, len(req.Users))
	resultChan := make(chan dto.BulkUserOperationResult, len(req.Users))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go u.createUserWorker(ctx, userChan, resultChan, &wg)
	}

	// Send users to workers
	go func() {
		defer close(userChan)
		for _, user := range req.Users {
			userChan <- user
		}
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Process results
	for result := range resultChan {
		response.Results = append(response.Results, result)
		if result.Success {
			response.Success++
		} else {
			response.Failed++
		}

		// Update status
		u.mu.Lock()
		status.Processed++
		status.Success = response.Success
		status.Failed = response.Failed
		u.mu.Unlock()
	}

	// Complete operation
	endTime := time.Now()
	u.mu.Lock()
	status.Status = "completed"
	status.EndTime = &endTime
	status.Results = response

	// Add to history
	if u.operationHistory["users"] == nil {
		u.operationHistory["users"] = make([]*BulkOperationHistory, 0)
	}

	history := &BulkOperationHistory{
		ID:         operationId,
		EntityType: "users",
		Operation:  "bulk_create",
		Status:     "completed",
		Total:      response.Total,
		Success:    response.Success,
		Failed:     response.Failed,
		Timestamp:  endTime,
		Duration:   endTime.Sub(status.StartTime).String(),
		Results:    response,
	}
	u.operationHistory["users"] = append(u.operationHistory["users"], history)

	// Keep only last 50 operations
	if len(u.operationHistory["users"]) > 50 {
		u.operationHistory["users"] = u.operationHistory["users"][1:]
	}
	u.mu.Unlock()

	logger.Log.WithField("operationId", operationId).
		WithField("success", response.Success).
		WithField("failed", response.Failed).
		Info("Bulk user creation completed")

	return response, nil
}

func (u *bulkUsecaseImpl) createUserWorker(ctx context.Context, userChan <-chan dto.CreateUserRequest, resultChan chan<- dto.BulkUserOperationResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for userReq := range userChan {
		result := dto.BulkUserOperationResult{
			Username: userReq.Username,
		}

		// Validate individual user
		if err := validator.Validate(&userReq); err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("Validation failed: %v", err)
			resultChan <- result
			continue
		}

		// Additional validation
		if err := userReq.ValidateAuthSpecific(); err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("Auth validation failed: %v", err)
			resultChan <- result
			continue
		}

		// Check if user already exists
		exists, err := u.userRepo.ExistsByUsername(ctx, userReq.Username)
		if err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("Failed to check user existence: %v", err)
			resultChan <- result
			continue
		}

		if exists {
			result.Success = false
			result.Error = "User already exists"
			resultChan <- result
			continue
		}

		// Check if user already exists
		existsEmail, err := u.userRepo.ExistsByEmail(ctx, userReq.Email)
		if err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("Failed to check email existence: %v", err)
			resultChan <- result
			continue
		}

		if existsEmail {
			result.Success = false
			result.Error = "Email already exists"
			resultChan <- result
			continue
		}
		if userReq.GroupName != "" {
			existsGroup, err := u.groupRepo.ExistsByName(ctx, userReq.GroupName)
			if err != nil {
				result.Success = false
				result.Error = fmt.Sprintf("Failed to check group existence: %v", err)
				resultChan <- result
				continue
			}

			if !existsGroup {
				result.Success = false
				result.Error = "Group not found"
				resultChan <- result
				continue
			}
		} else {
			userReq.GroupName = "__DEFAULT__" // Assign default group if not provided
		}
		// Convert DTO to entity
		user := &entities.User{
			Username:       userReq.Username,
			Email:          userReq.Email,
			Password:       userReq.Password,
			AuthMethod:     userReq.AuthMethod,
			GroupName:      userReq.GroupName,
			UserExpiration: userReq.UserExpiration,
			MacAddresses:   validator.ConvertMAC(userReq.MacAddresses),
			AccessControl:  userReq.AccessControl,
			IPAssignMode:   userReq.IPAssignMode,
			IPAddress:      userReq.IPAddress,
		}
		if err := u.validateUserAuthMethod(user); err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("Auth method validation failed: %v", err)
			resultChan <- result
			continue
		}

		// For LDAP users, verify they exist in LDAP
		if user.IsLDAPAuth() {
			if err := u.ldapClient.CheckUserExists(userReq.Username); err != nil {
				result.Success = false
				result.Error = fmt.Sprintf("LDAP user check failed: %v", err)
				resultChan <- result
				continue
			}
		}

		if len(user.MacAddresses) > 0 {
			macAddresses := validator.ConvertMAC(user.MacAddresses)
			user.MacAddresses = macAddresses
		}

		// Process user group if access control is provided
		if len(user.AccessControl) > 0 {
			accessControl, err := validator.ValidateAndFixIPs(user.AccessControl)
			if err != nil {
				result.Success = false
				result.Error = fmt.Sprintf("Invalid IP addresses: %v", err)
				resultChan <- result
				continue
			}
			user.AccessControl = accessControl
		}

		if user.IPAssignMode == "" {
			user.IPAssignMode = entities.IPAssignModeDynamic
		}

		helper := &userUsecaseImpl{userRepo: u.userRepo, groupRepo: u.groupRepo, ldapClient: u.ldapClient}
		switch user.IPAssignMode {
		case entities.IPAssignModeDynamic:
			ip, err := helper.assignDynamicIP(ctx, user.GroupName)
			if err != nil {
				result.Success = false
				result.Error = fmt.Sprintf("Failed to assign IP: %v", err)
				resultChan <- result
				continue
			}
			user.IPAddress = ip
		case entities.IPAssignModeStatic:
			if err := helper.validateStaticIP(ctx, user.GroupName, user.IPAddress, ""); err != nil {
				result.Success = false
				result.Error = fmt.Sprintf("Invalid static IP: %v", err)
				resultChan <- result
				continue
			}
		default:
			result.Success = false
			result.Error = "Invalid IP assign mode"
			resultChan <- result
			continue
		}

		// Create user
		if err := u.userRepo.Create(ctx, user); err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("Failed to create user: %v", err)
			resultChan <- result
			continue
		}

		result.Success = true
		result.Message = "User created successfully"
		resultChan <- result
	}
}

func (u *bulkUsecaseImpl) BulkUserActions(ctx context.Context, req *dto.BulkUserActionsRequest) (*dto.BulkActionResponse, error) {
	operationId := uuid.New().String()
	logger.Log.WithField("operationId", operationId).
		WithField("userCount", len(req.Usernames)).
		WithField("action", req.Action).
		Info("Starting bulk user actions")

	response := &dto.BulkActionResponse{
		Total:   len(req.Usernames),
		Success: 0,
		Failed:  0,
		Results: make([]dto.BulkUserOperationResult, 0, len(req.Usernames)),
	}

	for _, username := range req.Usernames {
		result := dto.BulkUserOperationResult{
			Username: username,
		}

		// Check if user exists
		_, err := u.userRepo.GetByUsername(ctx, username)
		if err != nil {
			result.Success = false
			result.Error = "User not found"
			response.Results = append(response.Results, result)
			response.Failed++
			continue
		}

		// Perform action
		var actionErr error
		switch req.Action {
		case "enable":
			actionErr = u.userRepo.Enable(ctx, username)
			result.Message = "User enabled successfully"
		case "disable":
			actionErr = u.userRepo.Disable(ctx, username)
			result.Message = "User disabled successfully"
		case "reset-otp":
			actionErr = u.userRepo.RegenerateTOTP(ctx, username)
			result.Message = "User OTP reset successfully"
		default:
			actionErr = fmt.Errorf("invalid action: %s", req.Action)
		}

		if actionErr != nil {
			result.Success = false
			result.Error = actionErr.Error()
			response.Failed++
		} else {
			result.Success = true
			response.Success++
		}

		response.Results = append(response.Results, result)
	}

	logger.Log.WithField("operationId", operationId).
		WithField("success", response.Success).
		WithField("failed", response.Failed).
		Info("Bulk user actions completed")

	return response, nil
}

func (u *bulkUsecaseImpl) BulkExtendUsers(ctx context.Context, req *dto.BulkUserExtendRequest) (*dto.BulkActionResponse, error) {
	operationId := uuid.New().String()
	logger.Log.WithField("operationId", operationId).
		WithField("userCount", len(req.Usernames)).
		WithField("newExpiration", req.NewExpiration).
		Info("Starting bulk user extension")

	response := &dto.BulkActionResponse{
		Total:   len(req.Usernames),
		Success: 0,
		Failed:  0,
		Results: make([]dto.BulkUserOperationResult, 0, len(req.Usernames)),
	}

	for _, username := range req.Usernames {
		result := dto.BulkUserOperationResult{
			Username: username,
		}

		// Check if user exists
		_, err := u.userRepo.GetByUsername(ctx, username)
		if err != nil {
			result.Success = false
			result.Error = "User not found"
			response.Results = append(response.Results, result)
			response.Failed++
			continue
		}

		// Update user expiration
		user := &entities.User{
			Username:       username,
			UserExpiration: req.NewExpiration,
		}

		if err := u.userRepo.Update(ctx, user); err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("Failed to extend user: %v", err)
			response.Failed++
		} else {
			result.Success = true
			result.Message = "User expiration extended successfully"
			response.Success++
		}

		response.Results = append(response.Results, result)
	}

	logger.Log.WithField("operationId", operationId).
		WithField("success", response.Success).
		WithField("failed", response.Failed).
		Info("Bulk user extension completed")

	return response, nil
}

func (u *bulkUsecaseImpl) ImportUsers(ctx context.Context, req *dto.ImportUsersRequest) (*dto.ImportResponse, error) {
	logger.Log.WithField("filename", req.File.Filename).
		WithField("format", req.Format).
		WithField("dryRun", req.DryRun).
		Info("Starting user import")

	// Read file content
	file, err := req.File.Open()
	if err != nil {
		return nil, errors.BadRequest("Failed to open file", err)
	}
	defer file.Close()

	content := make([]byte, req.File.Size)
	if _, err := file.Read(content); err != nil {
		return nil, errors.BadRequest("Failed to read file", err)
	}

	// Parse file
	users, validationErrors, err := u.ParseImportFile(req.File.Filename, content, req.Format, "users")
	if err != nil {
		return nil, errors.BadRequest("Failed to parse file", err)
	}

	userRequests, ok := users.([]dto.CreateUserRequest)
	if !ok {
		return nil, errors.InternalServerError("Invalid user data format", nil)
	}

	response := &dto.ImportResponse{
		Total:            len(userRequests),
		ValidRecords:     len(userRequests) - len(validationErrors),
		InvalidRecords:   len(validationErrors),
		DryRun:           req.DryRun,
		ValidationErrors: validationErrors,
	}

	// If dry run, return validation results only
	if req.DryRun {
		response.ProcessedRecords = 0
		response.SuccessCount = 0
		response.FailureCount = 0
		return response, nil
	}

	// Process valid users
	if response.ValidRecords > 0 {
		bulkReq := &dto.BulkCreateUsersRequest{
			Users: userRequests,
		}

		bulkResponse, err := u.BulkCreateUsers(ctx, bulkReq)
		if err != nil {
			return nil, err
		}

		response.ProcessedRecords = bulkResponse.Total
		response.SuccessCount = bulkResponse.Success
		response.FailureCount = bulkResponse.Failed
		response.Results = bulkResponse
	}

	logger.Log.WithField("total", response.Total).
		WithField("processed", response.ProcessedRecords).
		WithField("success", response.SuccessCount).
		Info("User import completed")

	return response, nil
}

// =================== BULK GROUP OPERATIONS ===================

func (u *bulkUsecaseImpl) BulkCreateGroups(ctx context.Context, req *dto.BulkCreateGroupsRequest) (*dto.BulkCreateGroupsResponse, error) {
	operationId := uuid.New().String()
	logger.Log.WithField("operationId", operationId).WithField("groupCount", len(req.Groups)).Info("Starting bulk group creation")

	response := &dto.BulkCreateGroupsResponse{
		Total:   len(req.Groups),
		Success: 0,
		Failed:  0,
		Results: make([]dto.BulkGroupOperationResult, 0, len(req.Groups)),
	}

	for _, groupReq := range req.Groups {
		result := dto.BulkGroupOperationResult{
			GroupName: groupReq.GroupName,
		}

		// Validate individual group
		if err := validator.Validate(&groupReq); err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("Validation failed: %v", err)
			response.Results = append(response.Results, result)
			response.Failed++
			continue
		}

		// Check for reserved group names
		if u.isReservedGroupName(groupReq.GroupName) {
			result.Success = false
			result.Error = "Group name is reserved and cannot be used"
			response.Results = append(response.Results, result)
			response.Failed++
			continue
		}

		// Check if group already exists
		exists, err := u.groupRepo.ExistsByName(ctx, groupReq.GroupName)
		if err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("Failed to check group existence: %v", err)
			response.Results = append(response.Results, result)
			response.Failed++
			continue
		}

		if exists {
			result.Success = false
			result.Error = "Group already exists"
			response.Results = append(response.Results, result)
			response.Failed++
			continue
		}

		// Set default values like in group handler
		mfa := true
		if groupReq.MFA != nil {
			mfa = *groupReq.MFA
		}

		role := entities.UserRoleUser
		if groupReq.Role != "" {
			role = groupReq.Role
		}

		// Convert DTO to entity
		group := &entities.Group{
			GroupName:     groupReq.GroupName,
			AuthMethod:    groupReq.AuthMethod,
			AccessControl: groupReq.AccessControl,
			Role:          role,
			GroupSubnet:   groupReq.GroupSubnet,
			GroupRange:    groupReq.GroupRange,
		}

		// Set MFA
		group.SetMFA(mfa)

		// Validate and fix IP addresses if provided
		if len(group.AccessControl) > 0 {
			accessControl, err := validator.ValidateAndFixIPs(group.AccessControl)
			if err != nil {
				result.Success = false
				result.Error = fmt.Sprintf("Invalid IP addresses: %v", err)
				response.Results = append(response.Results, result)
				response.Failed++
				continue
			}
			group.AccessControl = accessControl
		}

		// Create group
		if err := u.groupRepo.Create(ctx, group); err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("Failed to create group: %v", err)
			response.Failed++
		} else {
			result.Success = true
			result.Message = "Group created successfully"
			response.Success++
		}

		response.Results = append(response.Results, result)
	}

	logger.Log.WithField("operationId", operationId).
		WithField("success", response.Success).
		WithField("failed", response.Failed).
		Info("Bulk group creation completed")

	return response, nil
}

func (u *bulkUsecaseImpl) BulkGroupActions(ctx context.Context, req *dto.BulkGroupActionsRequest) (*dto.BulkGroupActionResponse, error) {
	operationId := uuid.New().String()
	logger.Log.WithField("operationId", operationId).
		WithField("groupCount", len(req.GroupNames)).
		WithField("action", req.Action).
		Info("Starting bulk group actions")

	response := &dto.BulkGroupActionResponse{
		Total:   len(req.GroupNames),
		Success: 0,
		Failed:  0,
		Results: make([]dto.BulkGroupOperationResult, 0, len(req.GroupNames)),
	}

	for _, groupName := range req.GroupNames {
		result := dto.BulkGroupOperationResult{
			GroupName: groupName,
		}

		// Check if group is system group
		if u.isSystemGroup(groupName) {
			result.Success = false
			result.Error = "Cannot modify system group"
			response.Results = append(response.Results, result)
			response.Failed++
			continue
		}

		// Check if group exists
		_, err := u.groupRepo.GetByName(ctx, groupName)
		if err != nil {
			result.Success = false
			result.Error = "Group not found"
			response.Results = append(response.Results, result)
			response.Failed++
			continue
		}

		// Perform action
		var actionErr error
		switch req.Action {
		case "enable":
			actionErr = u.groupRepo.Enable(ctx, groupName)
			result.Message = "Group enabled successfully"
		case "disable":
			actionErr = u.groupRepo.Disable(ctx, groupName)
			result.Message = "Group disabled successfully"
		default:
			actionErr = fmt.Errorf("invalid action: %s", req.Action)
		}

		if actionErr != nil {
			result.Success = false
			result.Error = actionErr.Error()
			response.Failed++
		} else {
			result.Success = true
			response.Success++
		}

		response.Results = append(response.Results, result)
	}

	logger.Log.WithField("operationId", operationId).
		WithField("success", response.Success).
		WithField("failed", response.Failed).
		Info("Bulk group actions completed")

	return response, nil
}

func (u *bulkUsecaseImpl) ImportGroups(ctx context.Context, req *dto.ImportGroupsRequest) (*dto.ImportResponse, error) {
	logger.Log.WithField("filename", req.File.Filename).
		WithField("format", req.Format).
		WithField("dryRun", req.DryRun).
		Info("Starting group import")

	// Read file content
	file, err := req.File.Open()
	if err != nil {
		return nil, errors.BadRequest("Failed to open file", err)
	}
	defer file.Close()

	content := make([]byte, req.File.Size)
	if _, err := file.Read(content); err != nil {
		return nil, errors.BadRequest("Failed to read file", err)
	}

	// Parse file
	groups, validationErrors, err := u.ParseImportFile(req.File.Filename, content, req.Format, "groups")
	if err != nil {
		return nil, errors.BadRequest("Failed to parse file", err)
	}

	groupRequests, ok := groups.([]dto.CreateGroupRequest)
	if !ok {
		return nil, errors.InternalServerError("Invalid group data format", nil)
	}

	response := &dto.ImportResponse{
		Total:            len(groupRequests),
		ValidRecords:     len(groupRequests) - len(validationErrors),
		InvalidRecords:   len(validationErrors),
		DryRun:           req.DryRun,
		ValidationErrors: validationErrors,
	}

	// If dry run, return validation results only
	if req.DryRun {
		response.ProcessedRecords = 0
		response.SuccessCount = 0
		response.FailureCount = 0
		return response, nil
	}

	// Process valid groups
	if response.ValidRecords > 0 {
		bulkReq := &dto.BulkCreateGroupsRequest{
			Groups: groupRequests,
		}

		bulkResponse, err := u.BulkCreateGroups(ctx, bulkReq)
		if err != nil {
			return nil, err
		}

		response.ProcessedRecords = bulkResponse.Total
		response.SuccessCount = bulkResponse.Success
		response.FailureCount = bulkResponse.Failed
		response.Results = bulkResponse
	}

	logger.Log.WithField("total", response.Total).
		WithField("processed", response.ProcessedRecords).
		WithField("success", response.SuccessCount).
		Info("Group import completed")

	return response, nil
}

// =================== TEMPLATE GENERATION ===================

func (u *bulkUsecaseImpl) GenerateUserTemplate(format string) (filename string, content []byte, error error) {
	switch format {
	case "csv":
		return u.generateUserCSVTemplate()
	case "xlsx":
		return u.generateUserXLSXTemplate()
	default:
		return "", nil, errors.BadRequest("Unsupported format", nil)
	}
}

func (u *bulkUsecaseImpl) GenerateGroupTemplate(format string) (filename string, content []byte, error error) {
	switch format {
	case "csv":
		return u.generateGroupCSVTemplate()
	case "xlsx":
		return u.generateGroupXLSXTemplate()
	default:
		return "", nil, errors.BadRequest("Unsupported format", nil)
	}
}

func (u *bulkUsecaseImpl) generateUserCSVTemplate() (string, []byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write headers
	headers := []string{
		"username", "email", "group_name", "password", "auth_method",
		"user_expiration", "mac_addresses", "access_control",
		"ip_assign_mode", "ip_address",
	}
	writer.Write(headers)

	// Write sample data
	sampleData := [][]string{
		{"testuser1", "test1@example.com", "Group", "SecurePass123!", "local", "31/12/2024", "AA:BB:CC:DD:EE:FF", "192.168.1.0/24", "dynamic", ""},
		{"ldapuser1", "ldap1@company.com", "Group", "", "ldap", "31/12/2024", "11:22:33:44:55:66", "10.0.0.0/8", "static", "10.0.0.10"},
	}

	for _, row := range sampleData {
		writer.Write(row)
	}

	writer.Flush()
	filename := "user_template.csv"
	return filename, buf.Bytes(), nil
}

func (u *bulkUsecaseImpl) generateUserXLSXTemplate() (string, []byte, error) {
	file := xlsx.NewFile()
	sheet, err := file.AddSheet("Users")
	if err != nil {
		return "", nil, err
	}

	// Headers
	headers := []string{
		"username", "email", "group_name", "password", "auth_method",
		"user_expiration", "mac_addresses", "access_control",
		"ip_assign_mode", "ip_address",
	}

	headerRow := sheet.AddRow()
	for _, header := range headers {
		cell := headerRow.AddCell()
		cell.Value = header
		cell.GetStyle().Font.Bold = true
	}

	// Sample data
	sampleData := [][]string{
		{"testuser1", "test1@example.com", "Group", "SecurePass123!", "local", "31/12/2024", "AA:BB:CC:DD:EE:FF", "192.168.1.0/24", "dynamic", ""},
		{"ldapuser1", "ldap1@company.com", "Group", "", "ldap", "31/12/2024", "11:22:33:44:55:66", "10.0.0.0/8", "static", "10.0.0.10"},
	}

	for _, rowData := range sampleData {
		row := sheet.AddRow()
		for _, cellData := range rowData {
			cell := row.AddCell()
			cell.Value = cellData
		}
	}

	var buf bytes.Buffer
	err = file.Write(&buf)
	if err != nil {
		return "", nil, err
	}

	filename := "user_template.xlsx"
	return filename, buf.Bytes(), nil
}

// Updated template generation to include new fields
func (u *bulkUsecaseImpl) generateGroupCSVTemplate() (string, []byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write headers - updated with new fields
	headers := []string{
		"group_name", "auth_method", "mfa", "role", "access_control",
		"group_subnet", "group_range",
	}
	writer.Write(headers)

	// Write sample data - updated with new fields
	sampleData := [][]string{
		{"ADMIN_GROUP", "local", "true", "Admin", "192.168.1.0/24,10.0.0.0/8", "10.8.0.0/24", "10.8.0.100-10.8.0.200"},
		{"USER_GROUP", "ldap", "true", "User", "192.168.2.0/24", "10.8.1.0/24", "10.8.1.100-10.8.1.200"},
		{"DEV_GROUP", "local", "false", "User", "10.0.0.0/8", "", ""},
	}

	for _, row := range sampleData {
		writer.Write(row)
	}

	writer.Flush()
	filename := "group_template.csv"
	return filename, buf.Bytes(), nil
}

func (u *bulkUsecaseImpl) generateGroupXLSXTemplate() (string, []byte, error) {
	file := xlsx.NewFile()
	sheet, err := file.AddSheet("Groups")
	if err != nil {
		return "", nil, err
	}

	// Headers - updated with new fields
	headers := []string{
		"group_name", "auth_method", "mfa", "role", "access_control",
		"group_subnet", "group_range",
	}

	headerRow := sheet.AddRow()
	for _, header := range headers {
		cell := headerRow.AddCell()
		cell.Value = header
		cell.GetStyle().Font.Bold = true
	}

	// Sample data - updated with new fields
	sampleData := [][]string{
		{"ADMIN_GROUP", "local", "true", "Admin", "192.168.1.0/24,10.0.0.0/8", "10.8.0.0/24", "10.8.0.100-10.8.0.200"},
		{"USER_GROUP", "ldap", "true", "User", "192.168.2.0/24", "10.8.1.0/24", "10.8.1.100-10.8.1.200"},
		{"DEV_GROUP", "local", "false", "User", "10.0.0.0/8", "", ""},
	}

	for _, rowData := range sampleData {
		row := sheet.AddRow()
		for _, cellData := range rowData {
			cell := row.AddCell()
			cell.Value = cellData
		}
	}

	var buf bytes.Buffer
	err = file.Write(&buf)
	if err != nil {
		return "", nil, err
	}

	filename := "group_template.xlsx"
	return filename, buf.Bytes(), nil
}

// =================== FILE PARSING ===================

func (u *bulkUsecaseImpl) ParseImportFile(filename string, content []byte, format string, entityType string) (interface{}, []dto.ImportValidationError, error) {
	switch format {
	case "csv":
		return u.parseCSVFile(content, entityType)
	case "json":
		return u.parseJSONFile(content, entityType)
	case "xlsx":
		return u.parseXLSXFile(content, entityType)
	default:
		return nil, nil, fmt.Errorf("unsupported format: %s", format)
	}
}

func (u *bulkUsecaseImpl) parseCSVFile(content []byte, entityType string) (interface{}, []dto.ImportValidationError, error) {
	reader := csv.NewReader(bytes.NewReader(content))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CSV: %v", err)
	}

	if len(records) < 2 {
		return nil, nil, fmt.Errorf("CSV file must contain headers and at least one data row")
	}

	headers := records[0]
	var validationErrors []dto.ImportValidationError

	switch entityType {
	case "groups":
		return u.parseGroupsFromCSV(headers, records[1:], &validationErrors)
	case "users":
		return u.parseUsersFromCSV(headers, records[1:], &validationErrors)
	default:
		return nil, nil, fmt.Errorf("unsupported entity type: %s", entityType)
	}
}

func (u *bulkUsecaseImpl) parseGroupsFromCSV(headers []string, records [][]string, validationErrors *[]dto.ImportValidationError) ([]dto.CreateGroupRequest, []dto.ImportValidationError, error) {
	var groups []dto.CreateGroupRequest

	// Create header index map for flexible column ordering
	headerMap := make(map[string]int)
	for i, header := range headers {
		headerMap[strings.TrimSpace(strings.ToLower(header))] = i
	}

	for rowIdx, record := range records {
		group := dto.CreateGroupRequest{}

		// Required field: group_name
		if idx, exists := headerMap["group_name"]; exists && idx < len(record) {
			group.GroupName = strings.TrimSpace(record[idx])
		}
		if group.GroupName == "" {
			*validationErrors = append(*validationErrors, dto.ImportValidationError{
				Row:     rowIdx + 2, // +2 because we start from header row
				Field:   "group_name",
				Value:   "",
				Message: "Group name is required",
			})
			continue
		}

		// Required field: auth_method
		if idx, exists := headerMap["auth_method"]; exists && idx < len(record) {
			group.AuthMethod = strings.TrimSpace(record[idx])
		}
		if group.AuthMethod == "" {
			group.AuthMethod = "local" // Default value
		}

		// Optional field: mfa
		if idx, exists := headerMap["mfa"]; exists && idx < len(record) {
			mfaStr := strings.TrimSpace(strings.ToLower(record[idx]))
			if mfaStr != "" {
				mfa := mfaStr == "true" || mfaStr == "1" || mfaStr == "yes"
				group.MFA = &mfa
			}
		}

		// Optional field: role
		if idx, exists := headerMap["role"]; exists && idx < len(record) {
			role := strings.TrimSpace(record[idx])
			if role != "" {
				group.Role = role
			}
		}

		// Optional field: access_control (comma-separated IPs)
		if idx, exists := headerMap["access_control"]; exists && idx < len(record) {
			accessControlStr := strings.TrimSpace(record[idx])
			if accessControlStr != "" {
				group.AccessControl = strings.Split(accessControlStr, ",")
				for i, ip := range group.AccessControl {
					group.AccessControl[i] = strings.TrimSpace(ip)
				}
			}
		}

		// Optional field: group_subnet (comma-separated subnets)
		if idx, exists := headerMap["group_subnet"]; exists && idx < len(record) {
			subnetStr := strings.TrimSpace(record[idx])
			if subnetStr != "" {
				group.GroupSubnet = strings.Split(subnetStr, ",")
				for i, subnet := range group.GroupSubnet {
					group.GroupSubnet[i] = strings.TrimSpace(subnet)
				}
			}
		}

		// Optional field: group_range (comma-separated ranges)
		if idx, exists := headerMap["group_range"]; exists && idx < len(record) {
			rangeStr := strings.TrimSpace(record[idx])
			if rangeStr != "" {
				group.GroupRange = strings.Split(rangeStr, ",")
				for i, r := range group.GroupRange {
					group.GroupRange[i] = strings.TrimSpace(r)
				}
			}
		}

		// Validate individual group
		if err := validator.Validate(&group); err != nil {
			*validationErrors = append(*validationErrors, dto.ImportValidationError{
				Row:     rowIdx + 2,
				Field:   "group",
				Value:   group.GroupName,
				Message: fmt.Sprintf("Validation failed: %v", err),
			})
			continue
		}

		groups = append(groups, group)
	}

	return groups, *validationErrors, nil
}

func (u *bulkUsecaseImpl) parseUsersFromCSV(headers []string, records [][]string, validationErrors *[]dto.ImportValidationError) ([]dto.CreateUserRequest, []dto.ImportValidationError, error) {
	var users []dto.CreateUserRequest

	// Create header index map
	headerMap := make(map[string]int)
	for i, header := range headers {
		headerMap[strings.TrimSpace(strings.ToLower(header))] = i
	}

	for rowIdx, record := range records {
		user := dto.CreateUserRequest{}

		// Required field: username
		if idx, exists := headerMap["username"]; exists && idx < len(record) {
			user.Username = strings.TrimSpace(record[idx])
		}
		if user.Username == "" {
			*validationErrors = append(*validationErrors, dto.ImportValidationError{
				Row:     rowIdx + 2,
				Field:   "username",
				Value:   "",
				Message: "Username is required",
			})
			continue
		}

		// Parse other fields similarly...
		if idx, exists := headerMap["email"]; exists && idx < len(record) {
			user.Email = strings.TrimSpace(record[idx])
		}
		if idx, exists := headerMap["group_name"]; exists && idx < len(record) {
			user.GroupName = strings.TrimSpace(record[idx])
		}
		if idx, exists := headerMap["password"]; exists && idx < len(record) {
			user.Password = strings.TrimSpace(record[idx])
		}
		if idx, exists := headerMap["auth_method"]; exists && idx < len(record) {
			user.AuthMethod = strings.TrimSpace(record[idx])
		}
		if idx, exists := headerMap["user_expiration"]; exists && idx < len(record) {
			user.UserExpiration = strings.TrimSpace(record[idx])
		}
		if idx, exists := headerMap["mac_addresses"]; exists && idx < len(record) {
			macStr := strings.TrimSpace(record[idx])
			if macStr != "" {
				user.MacAddresses = strings.Split(macStr, ",")
				for i, mac := range user.MacAddresses {
					user.MacAddresses[i] = strings.TrimSpace(mac)
				}
			}
		}
		if idx, exists := headerMap["access_control"]; exists && idx < len(record) {
			accessStr := strings.TrimSpace(record[idx])
			if accessStr != "" {
				user.AccessControl = strings.Split(accessStr, ",")
				for i, ac := range user.AccessControl {
					user.AccessControl[i] = strings.TrimSpace(ac)
				}
			}
		}

		if idx, exists := headerMap["ip_assign_mode"]; exists && idx < len(record) {
			user.IPAssignMode = strings.TrimSpace(record[idx])
		}
		if idx, exists := headerMap["ip_address"]; exists && idx < len(record) {
			user.IPAddress = strings.TrimSpace(record[idx])
		}
		if user.IPAssignMode == "" {
			user.IPAssignMode = entities.IPAssignModeDynamic
		}

		// Validate individual user
		if err := validator.Validate(&user); err != nil {
			*validationErrors = append(*validationErrors, dto.ImportValidationError{
				Row:     rowIdx + 2,
				Field:   "user",
				Value:   user.Username,
				Message: fmt.Sprintf("Validation failed: %v", err),
			})
			continue
		}

		users = append(users, user)
	}

	return users, *validationErrors, nil
}

func (u *bulkUsecaseImpl) parseJSONFile(content []byte, entityType string) (interface{}, []dto.ImportValidationError, error) {
	var validationErrors []dto.ImportValidationError

	if entityType == "users" {
		var users []dto.CreateUserRequest
		if err := json.Unmarshal(content, &users); err != nil {
			return nil, nil, err
		}

		// Validate each user
		validUsers := make([]dto.CreateUserRequest, 0)
		for i, user := range users {
			if err := validator.Validate(&user); err != nil {
				validationErrors = append(validationErrors, dto.ImportValidationError{
					Row:     i + 1,
					Field:   "validation",
					Value:   user.Username,
					Message: err.Error(),
				})
				continue
			}
			validUsers = append(validUsers, user)
		}

		return validUsers, validationErrors, nil
	} else if entityType == "groups" {
		var groups []dto.CreateGroupRequest
		if err := json.Unmarshal(content, &groups); err != nil {
			return nil, nil, err
		}

		// Validate each group
		validGroups := make([]dto.CreateGroupRequest, 0)
		for i, group := range groups {
			if err := validator.Validate(&group); err != nil {
				validationErrors = append(validationErrors, dto.ImportValidationError{
					Row:     i + 1,
					Field:   "validation",
					Value:   group.GroupName,
					Message: err.Error(),
				})
				continue
			}
			validGroups = append(validGroups, group)
		}

		return validGroups, validationErrors, nil
	}

	return nil, nil, fmt.Errorf("unsupported entity type: %s", entityType)
}

func (u *bulkUsecaseImpl) parseXLSXFile(content []byte, entityType string) (interface{}, []dto.ImportValidationError, error) {
	// Similar to CSV parsing but using XLSX library
	// Implementation would parse XLSX format and return appropriate structures
	return nil, nil, fmt.Errorf("XLSX parsing not implemented yet")
}

// =================== HELPER FUNCTIONS ===================

// Helper functions
func (u *bulkUsecaseImpl) isReservedGroupName(groupName string) bool {
	reservedNames := []string{"__DEFAULT__", "admin", "root", "system", "default"}
	for _, reserved := range reservedNames {
		if strings.EqualFold(groupName, reserved) {
			return true
		}
	}
	return false
}

func (u *bulkUsecaseImpl) isSystemGroup(groupName string) bool {
	systemGroups := []string{"__DEFAULT__", "admin", "system"}
	for _, systemGroup := range systemGroups {
		if strings.EqualFold(groupName, systemGroup) {
			return true
		}
	}
	return false
}
func (u *bulkUsecaseImpl) GetBulkOperationHistory(ctx context.Context, entityType string, limit int) ([]interface{}, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	history, exists := u.operationHistory[entityType]
	if !exists || len(history) == 0 {
		return []interface{}{}, nil
	}

	// Sort by timestamp (newest first)
	sortedHistory := make([]*BulkOperationHistory, len(history))
	copy(sortedHistory, history)

	for i := 0; i < len(sortedHistory)-1; i++ {
		for j := i + 1; j < len(sortedHistory); j++ {
			if sortedHistory[i].Timestamp.Before(sortedHistory[j].Timestamp) {
				sortedHistory[i], sortedHistory[j] = sortedHistory[j], sortedHistory[i]
			}
		}
	}

	// Apply limit
	if limit > 0 && len(sortedHistory) > limit {
		sortedHistory = sortedHistory[:limit]
	}

	// Convert to interface{}
	result := make([]interface{}, len(sortedHistory))
	for i, h := range sortedHistory {
		result[i] = map[string]interface{}{
			"id":          h.ID,
			"entityType":  h.EntityType,
			"operation":   h.Operation,
			"status":      h.Status,
			"total":       h.Total,
			"success":     h.Success,
			"failed":      h.Failed,
			"timestamp":   h.Timestamp,
			"duration":    h.Duration,
			"successRate": u.calculateSuccessRate(h.Success, h.Total),
		}
	}

	return result, nil
}

func (u *bulkUsecaseImpl) GetBulkOperationStatus(ctx context.Context, operationId string) (interface{}, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	status, exists := u.operationStatus[operationId]
	if !exists {
		return nil, errors.NotFound("Operation not found", nil)
	}

	return map[string]interface{}{
		"id":         status.ID,
		"entityType": status.EntityType,
		"operation":  status.Operation,
		"status":     status.Status,
		"total":      status.Total,
		"processed":  status.Processed,
		"success":    status.Success,
		"failed":     status.Failed,
		"startTime":  status.StartTime,
		"endTime":    status.EndTime,
		"duration":   u.calculateDuration(status.StartTime, status.EndTime),
		"error":      status.Error,
		"progress":   u.calculateProgress(status.Processed, status.Total),
	}, nil
}

func (u *bulkUsecaseImpl) ValidateGroupBatch(groups []dto.CreateGroupRequest) ([]dto.CreateGroupRequest, []dto.ImportValidationError, error) {
	var validGroups []dto.CreateGroupRequest
	var validationErrors []dto.ImportValidationError

	for i, group := range groups {
		if err := validator.Validate(&group); err != nil {
			validationErrors = append(validationErrors, dto.ImportValidationError{
				Row:     i + 1,
				Field:   "validation",
				Value:   group.GroupName,
				Message: err.Error(),
			})
			continue
		}

		validGroups = append(validGroups, group)
	}

	return validGroups, validationErrors, nil
}

func (u *bulkUsecaseImpl) ValidateUserBatch(users []dto.CreateUserRequest) ([]dto.CreateUserRequest, []dto.ImportValidationError, error) {
	var validUsers []dto.CreateUserRequest
	var validationErrors []dto.ImportValidationError

	for i, user := range users {
		if err := validator.Validate(&user); err != nil {
			validationErrors = append(validationErrors, dto.ImportValidationError{
				Row:     i + 1,
				Field:   "validation",
				Value:   user.Username,
				Message: err.Error(),
			})
			continue
		}

		if err := user.ValidateAuthSpecific(); err != nil {
			validationErrors = append(validationErrors, dto.ImportValidationError{
				Row:     i + 1,
				Field:   "auth_validation",
				Value:   user.Username,
				Message: err.Error(),
			})
			continue
		}

		validUsers = append(validUsers, user)
	}

	return validUsers, validationErrors, nil
}
func (u *bulkUsecaseImpl) calculateDuration(startTime time.Time, endTime *time.Time) string {
	if endTime == nil {
		return time.Since(startTime).String()
	}
	return endTime.Sub(startTime).String()
}
func (u *bulkUsecaseImpl) calculateProgress(processed, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(processed) / float64(total) * 100
}
func (u *bulkUsecaseImpl) calculateSuccessRate(success, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(success) / float64(total) * 100
}
func (u *bulkUsecaseImpl) validateUserAuthMethod(user *entities.User) error {
	authMethod := strings.ToLower(strings.TrimSpace(user.AuthMethod))

	switch authMethod {
	case "local":
		// Local users must have password during creation
		if strings.TrimSpace(user.Password) == "" {
			return fmt.Errorf("password is required for local users")
		}

		// Validate password complexity
		if err := u.validatePasswordComplexity(user.Password); err != nil {
			return fmt.Errorf("password validation failed: %w", err)
		}

	case "ldap":
		// LDAP users should not have password set during creation
		if strings.TrimSpace(user.Password) != "" {
			logger.Log.WithField("username", user.Username).
				Warn("Password provided for LDAP user during creation - clearing password")
			user.Password = "" // Clear password for LDAP users
		}

	default:
		return fmt.Errorf("invalid authentication method: %s", user.AuthMethod)
	}

	return nil
}
func (u *bulkUsecaseImpl) validatePasswordComplexity(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	if len(password) > 128 {
		return fmt.Errorf("password must not exceed 128 characters")
	}

	return nil
}
