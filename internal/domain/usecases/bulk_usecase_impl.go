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

		// For LDAP users, verify they exist in LDAP
		if userReq.AuthMethod == "ldap" {
			if err := u.ldapClient.CheckUserExists(userReq.Username); err != nil {
				result.Success = false
				result.Error = fmt.Sprintf("LDAP user check failed: %v", err)
				resultChan <- result
				continue
			}
		}

		// Convert DTO to entity
		user := &entities.User{
			Username:       userReq.Username,
			Email:          userReq.Email,
			Password:       userReq.Password,
			AuthMethod:     userReq.AuthMethod,
			UserExpiration: userReq.UserExpiration,
			MacAddresses:   validator.ConvertMAC(userReq.MacAddresses),
			AccessControl:  userReq.AccessControl,
		}

		// Process user group if access control is provided
		if len(user.AccessControl) > 0 {
			groupName := strings.ToUpper(user.Username) + "_GR"

			// Create group
			group := entities.NewGroup(groupName, user.AuthMethod)
			accessControl, err := validator.ValidateAndFixIPs(user.AccessControl)
			if err != nil {
				result.Success = false
				result.Error = fmt.Sprintf("Invalid IP addresses: %v", err)
				resultChan <- result
				continue
			}
			group.AccessControl = accessControl

			if err := u.groupRepo.Create(ctx, group); err != nil {
				result.Success = false
				result.Error = fmt.Sprintf("Failed to create user group: %v", err)
				resultChan <- result
				continue
			}

			user.GroupName = groupName
		} else {
			user.GroupName = "__DEFAULT__"
		}

		// Create user
		if err := u.userRepo.Create(ctx, user); err != nil {
			// Cleanup group if user creation fails
			if user.GroupName != "__DEFAULT__" {
				u.groupRepo.Delete(ctx, user.GroupName)
			}
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

		// Convert DTO to entity
		group := &entities.Group{
			GroupName:     groupReq.GroupName,
			AuthMethod:    groupReq.AuthMethod,
			AccessControl: groupReq.AccessControl,
		}

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
		"username", "email", "password", "auth_method",
		"user_expiration", "mac_addresses", "access_control",
	}
	writer.Write(headers)

	// Write sample data
	sampleData := [][]string{
		{"testuser1", "test1@example.com", "SecurePass123!", "local", "31/12/2024", "AA:BB:CC:DD:EE:FF", "192.168.1.0/24"},
		{"ldapuser1", "ldap1@company.com", "", "ldap", "31/12/2024", "11:22:33:44:55:66", "10.0.0.0/8"},
	}

	for _, row := range sampleData {
		writer.Write(row)
	}

	writer.Flush()

	filename := fmt.Sprintf("user_template_%s.csv", time.Now().Format("20060102"))
	return filename, buf.Bytes(), nil
}

func (u *bulkUsecaseImpl) generateGroupCSVTemplate() (string, []byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write headers
	headers := []string{"group_name", "auth_method", "access_control"}
	writer.Write(headers)

	// Write sample data
	sampleData := [][]string{
		{"ADMIN_GROUP", "local", "192.168.1.0/24,10.0.0.0/8"},
		{"USER_GROUP", "ldap", "192.168.2.0/24"},
	}

	for _, row := range sampleData {
		writer.Write(row)
	}

	writer.Flush()

	filename := fmt.Sprintf("group_template_%s.csv", time.Now().Format("20060102"))
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
		"username", "email", "password", "auth_method",
		"user_expiration", "mac_addresses", "access_control",
	}

	headerRow := sheet.AddRow()
	for _, header := range headers {
		cell := headerRow.AddCell()
		cell.Value = header
		cell.GetStyle().Font.Bold = true
	}

	// Sample data
	sampleData := [][]string{
		{"testuser1", "test1@example.com", "SecurePass123!", "local", "31/12/2024", "AA:BB:CC:DD:EE:FF", "192.168.1.0/24"},
		{"ldapuser1", "ldap1@company.com", "", "ldap", "31/12/2024", "11:22:33:44:55:66", "10.0.0.0/8"},
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

	filename := fmt.Sprintf("user_template_%s.xlsx", time.Now().Format("20060102"))
	return filename, buf.Bytes(), nil
}

func (u *bulkUsecaseImpl) generateGroupXLSXTemplate() (string, []byte, error) {
	file := xlsx.NewFile()
	sheet, err := file.AddSheet("Groups")
	if err != nil {
		return "", nil, err
	}

	// Headers
	headers := []string{"group_name", "auth_method", "access_control"}

	headerRow := sheet.AddRow()
	for _, header := range headers {
		cell := headerRow.AddCell()
		cell.Value = header
		cell.GetStyle().Font.Bold = true
	}

	// Sample data
	sampleData := [][]string{
		{"ADMIN_GROUP", "local", "192.168.1.0/24,10.0.0.0/8"},
		{"USER_GROUP", "ldap", "192.168.2.0/24"},
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

	filename := fmt.Sprintf("group_template_%s.xlsx", time.Now().Format("20060102"))
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
		return nil, nil, err
	}

	if len(records) < 2 { // At least header + 1 data row
		return nil, nil, fmt.Errorf("file must contain at least header and one data row")
	}

	headers := records[0]
	var validationErrors []dto.ImportValidationError

	if entityType == "users" {
		var users []dto.CreateUserRequest

		for i, record := range records[1:] {
			rowNum := i + 2 // +2 because we skip header and arrays are 0-indexed

			if len(record) != len(headers) {
				validationErrors = append(validationErrors, dto.ImportValidationError{
					Row:     rowNum,
					Field:   "general",
					Value:   "",
					Message: "Column count mismatch",
				})
				continue
			}

			user := dto.CreateUserRequest{}

			for j, value := range record {
				value = strings.TrimSpace(value)
				switch strings.ToLower(headers[j]) {
				case "username":
					user.Username = value
				case "email":
					user.Email = value
				case "password":
					user.Password = value
				case "auth_method":
					user.AuthMethod = value
				case "user_expiration":
					user.UserExpiration = value
				case "mac_addresses":
					if value != "" {
						user.MacAddresses = strings.Split(value, ",")
						for k, mac := range user.MacAddresses {
							user.MacAddresses[k] = strings.TrimSpace(mac)
						}
					}
				case "access_control":
					if value != "" {
						user.AccessControl = strings.Split(value, ",")
						for k, ac := range user.AccessControl {
							user.AccessControl[k] = strings.TrimSpace(ac)
						}
					}
				}
			}

			// Validate user
			if err := validator.Validate(&user); err != nil {
				validationErrors = append(validationErrors, dto.ImportValidationError{
					Row:     rowNum,
					Field:   "validation",
					Value:   user.Username,
					Message: err.Error(),
				})
				continue
			}

			users = append(users, user)
		}

		return users, validationErrors, nil
	} else if entityType == "groups" {
		var groups []dto.CreateGroupRequest

		for i, record := range records[1:] {
			rowNum := i + 2

			if len(record) != len(headers) {
				validationErrors = append(validationErrors, dto.ImportValidationError{
					Row:     rowNum,
					Field:   "general",
					Value:   "",
					Message: "Column count mismatch",
				})
				continue
			}

			group := dto.CreateGroupRequest{}

			for j, value := range record {
				value = strings.TrimSpace(value)
				switch strings.ToLower(headers[j]) {
				case "group_name":
					group.GroupName = value
				case "auth_method":
					group.AuthMethod = value
				case "access_control":
					if value != "" {
						group.AccessControl = strings.Split(value, ",")
						for k, ac := range group.AccessControl {
							group.AccessControl[k] = strings.TrimSpace(ac)
						}
					}
				}
			}

			// Validate group
			if err := validator.Validate(&group); err != nil {
				validationErrors = append(validationErrors, dto.ImportValidationError{
					Row:     rowNum,
					Field:   "validation",
					Value:   group.GroupName,
					Message: err.Error(),
				})
				continue
			}

			groups = append(groups, group)
		}

		return groups, validationErrors, nil
	}

	return nil, nil, fmt.Errorf("unsupported entity type: %s", entityType)
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
	file, err := xlsx.OpenBinary(content)
	if err != nil {
		return nil, nil, err
	}

	if len(file.Sheets) == 0 {
		return nil, nil, fmt.Errorf("no sheets found in XLSX file")
	}

	sheet := file.Sheets[0]

	// Get max row and col to iterate properly
	maxRow := sheet.MaxRow
	maxCol := sheet.MaxCol

	if maxRow < 2 {
		return nil, nil, fmt.Errorf("file must contain at least header and one data row")
	}

	// Get headers from first row
	headers := make([]string, maxCol)
	for col := 0; col < maxCol; col++ {
		cell, err := sheet.Cell(0, col)
		if err != nil {
			continue
		}
		headers[col] = strings.TrimSpace(cell.String())
	}

	var validationErrors []dto.ImportValidationError

	if entityType == "users" {
		var users []dto.CreateUserRequest

		for row := 1; row < maxRow; row++ {
			rowNum := row + 1
			user := dto.CreateUserRequest{}

			for col := 0; col < maxCol && col < len(headers); col++ {
				cell, err := sheet.Cell(row, col)
				if err != nil {
					continue
				}

				value := strings.TrimSpace(cell.String())
				switch strings.ToLower(headers[col]) {
				case "username":
					user.Username = value
				case "email":
					user.Email = value
				case "password":
					user.Password = value
				case "auth_method":
					user.AuthMethod = value
				case "user_expiration":
					user.UserExpiration = value
				case "mac_addresses":
					if value != "" {
						user.MacAddresses = strings.Split(value, ",")
						for k, mac := range user.MacAddresses {
							user.MacAddresses[k] = strings.TrimSpace(mac)
						}
					}
				case "access_control":
					if value != "" {
						user.AccessControl = strings.Split(value, ",")
						for k, ac := range user.AccessControl {
							user.AccessControl[k] = strings.TrimSpace(ac)
						}
					}
				}
			}

			// Skip empty rows
			if user.Username == "" {
				continue
			}

			// Validate user
			if err := validator.Validate(&user); err != nil {
				validationErrors = append(validationErrors, dto.ImportValidationError{
					Row:     rowNum,
					Field:   "validation",
					Value:   user.Username,
					Message: err.Error(),
				})
				continue
			}

			users = append(users, user)
		}

		return users, validationErrors, nil
	} else if entityType == "groups" {
		var groups []dto.CreateGroupRequest

		for row := 1; row < maxRow; row++ {
			rowNum := row + 1
			group := dto.CreateGroupRequest{}

			for col := 0; col < maxCol && col < len(headers); col++ {
				cell, err := sheet.Cell(row, col)
				if err != nil {
					continue
				}

				value := strings.TrimSpace(cell.String())
				switch strings.ToLower(headers[col]) {
				case "group_name":
					group.GroupName = value
				case "auth_method":
					group.AuthMethod = value
				case "access_control":
					if value != "" {
						group.AccessControl = strings.Split(value, ",")
						for k, ac := range group.AccessControl {
							group.AccessControl[k] = strings.TrimSpace(ac)
						}
					}
				}
			}

			// Skip empty rows
			if group.GroupName == "" {
				continue
			}

			// Validate group
			if err := validator.Validate(&group); err != nil {
				validationErrors = append(validationErrors, dto.ImportValidationError{
					Row:     rowNum,
					Field:   "validation",
					Value:   group.GroupName,
					Message: err.Error(),
				})
				continue
			}

			groups = append(groups, group)
		}

		return groups, validationErrors, nil
	}

	return nil, nil, fmt.Errorf("unsupported entity type: %s", entityType)
}

// =================== VALIDATION HELPERS ===================

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

// =================== OPERATION TRACKING ===================

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

// =================== HELPER METHODS ===================

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
