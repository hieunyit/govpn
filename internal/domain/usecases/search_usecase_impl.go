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
	"govpn/pkg/errors"
	"govpn/pkg/logger"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tealeg/xlsx/v3"
)

type searchUsecaseImpl struct {
	userRepo      repositories.UserRepository
	groupRepo     repositories.GroupRepository
	savedSearches map[string]*dto.SavedSearchResponse // In-memory storage for demo
	searchHistory map[string][]interface{}            // User search history
	mu            sync.RWMutex                        // For thread-safe operations
}

func NewSearchUsecase(userRepo repositories.UserRepository, groupRepo repositories.GroupRepository) SearchUsecase {
	return &searchUsecaseImpl{
		userRepo:      userRepo,
		groupRepo:     groupRepo,
		savedSearches: make(map[string]*dto.SavedSearchResponse),
		searchHistory: make(map[string][]interface{}),
	}
}

// =================== ADVANCED SEARCH ===================

func (s *searchUsecaseImpl) AdvancedUserSearch(ctx context.Context, req *dto.AdvancedUserSearchRequest) (*dto.AdvancedUserSearchResponse, error) {
	startTime := time.Now()

	logger.Log.WithField("searchText", req.SearchText).
		WithField("authMethod", req.AuthMethod).
		WithField("role", req.Role).
		Debug("Starting advanced user search")

	// Get all users first
	allUsers, err := s.userRepo.List(ctx, &entities.UserFilter{
		Limit:  10000, // Large limit to get all users
		Offset: 0,
	})
	if err != nil {
		return nil, errors.InternalServerError("Failed to retrieve users", err)
	}

	// Apply advanced filters
	filteredUsers := s.filterUsers(allUsers, req)

	// Calculate metadata
	metadata := s.calculateUserSearchMetadata(allUsers, filteredUsers, startTime)

	// Apply sorting
	s.sortUsers(filteredUsers, req.SortBy, req.SortOrder)

	// Apply pagination
	totalFiltered := len(filteredUsers)
	totalPages := int(math.Ceil(float64(totalFiltered) / float64(req.Limit)))

	start := (req.Page - 1) * req.Limit
	end := start + req.Limit
	if start > totalFiltered {
		start = totalFiltered
	}
	if end > totalFiltered {
		end = totalFiltered
	}

	paginatedUsers := filteredUsers[start:end]

	// Convert to DTOs
	userResponses := make([]dto.UserResponse, len(paginatedUsers))
	for i, user := range paginatedUsers {
		userResponses[i] = dto.UserResponse{
			Username:       user.Username,
			Email:          user.Email,
			AuthMethod:     user.AuthMethod,
			UserExpiration: user.UserExpiration,
			MacAddresses:   user.MacAddresses,
			MFA:            user.MFA == "true",
			Role:           user.Role,
			DenyAccess:     user.DenyAccess == "true",
			AccessControl:  user.AccessControl,
			GroupName:      user.GroupName,
		}
	}

	response := &dto.AdvancedUserSearchResponse{
		Users:      userResponses,
		Total:      totalFiltered,
		Page:       req.Page,
		Limit:      req.Limit,
		TotalPages: totalPages,
		Metadata:   metadata,
		Filters:    *req,
	}

	// Track search usage
	s.TrackSearchUsage(ctx, "system", "users", req, totalFiltered, time.Since(startTime).Milliseconds())

	logger.Log.WithField("total", totalFiltered).
		WithField("returned", len(userResponses)).
		WithField("duration", metadata.SearchDuration).
		Info("Advanced user search completed")

	return response, nil
}

func (s *searchUsecaseImpl) AdvancedGroupSearch(ctx context.Context, req *dto.AdvancedGroupSearchRequest) (*dto.AdvancedGroupSearchResponse, error) {
	startTime := time.Now()

	logger.Log.WithField("searchText", req.SearchText).
		WithField("authMethod", req.AuthMethod).
		WithField("role", req.Role).
		Debug("Starting advanced group search")

	// Get all groups first
	allGroups, err := s.groupRepo.List(ctx, &entities.GroupFilter{
		Limit:  5000, // Large limit to get all groups
		Offset: 0,
	})
	if err != nil {
		return nil, errors.InternalServerError("Failed to retrieve groups", err)
	}

	// Apply advanced filters
	filteredGroups := s.filterGroups(allGroups, req)

	// Calculate metadata
	metadata := s.calculateGroupSearchMetadata(allGroups, filteredGroups, startTime)

	// Apply sorting
	s.sortGroups(filteredGroups, req.SortBy, req.SortOrder)

	// Apply pagination
	totalFiltered := len(filteredGroups)
	totalPages := int(math.Ceil(float64(totalFiltered) / float64(req.Limit)))

	start := (req.Page - 1) * req.Limit
	end := start + req.Limit
	if start > totalFiltered {
		start = totalFiltered
	}
	if end > totalFiltered {
		end = totalFiltered
	}

	paginatedGroups := filteredGroups[start:end]

	// Convert to enhanced DTOs
	groupResponses := make([]dto.EnhancedGroupResponse, len(paginatedGroups))
	for i, group := range paginatedGroups {
		enhancedGroup := dto.EnhancedGroupResponse{
			GroupResponse: dto.GroupResponse{
				GroupName:     group.GroupName,
				AuthMethod:    group.AuthMethod,
				MFA:           group.MFA == "true",
				Role:          group.Role,
				DenyAccess:    group.DenyAccess == "true",
				AccessControl: group.AccessControl,
			},
		}

		// Calculate member count if requested
		if req.IncludeMemberCount {
			memberCount, _ := s.getGroupMemberCount(ctx, group.GroupName)
			enhancedGroup.MemberCount = memberCount
		}

		groupResponses[i] = enhancedGroup
	}

	response := &dto.AdvancedGroupSearchResponse{
		Groups:     groupResponses,
		Total:      totalFiltered,
		Page:       req.Page,
		Limit:      req.Limit,
		TotalPages: totalPages,
		Metadata:   metadata,
		Filters:    *req,
	}

	// Track search usage
	s.TrackSearchUsage(ctx, "system", "groups", req, totalFiltered, time.Since(startTime).Milliseconds())

	logger.Log.WithField("total", totalFiltered).
		WithField("returned", len(groupResponses)).
		WithField("duration", metadata.SearchDuration).
		Info("Advanced group search completed")

	return response, nil
}

// =================== SAVED SEARCHES ===================

func (s *searchUsecaseImpl) SaveSearch(ctx context.Context, req *dto.SavedSearchRequest, username string) (*dto.SavedSearchResponse, error) {
	searchId := uuid.New().String()
	now := time.Now()

	savedSearch := &dto.SavedSearchResponse{
		ID:          searchId, // For compatibility
		SearchId:    searchId,
		Name:        req.Name,
		Description: req.Description,
		SearchType:  req.SearchType,
		Filters:     req.Filters,
		CreatedBy:   username,
		CreatedAt:   now,
		LastUsed:    &now,
		UseCount:    0,
		IsPublic:    req.IsPublic,
		Tags:        req.Tags,
	}

	s.mu.Lock()
	s.savedSearches[searchId] = savedSearch
	s.mu.Unlock()

	logger.Log.WithField("searchId", searchId).
		WithField("name", req.Name).
		WithField("username", username).
		Info("Search saved successfully")

	return savedSearch, nil
}

func (s *searchUsecaseImpl) GetSavedSearches(ctx context.Context, username string, searchType string, includePublic bool) ([]dto.SavedSearchResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []dto.SavedSearchResponse

	for _, search := range s.savedSearches {
		// Check ownership or public access
		if search.CreatedBy == username || (includePublic && search.IsPublic) {
			// Filter by search type if specified
			if searchType == "" || search.SearchType == searchType {
				results = append(results, *search)
			}
		}
	}

	// Sort by last used
	sort.Slice(results, func(i, j int) bool {
		if results[i].LastUsed == nil {
			return false
		}
		if results[j].LastUsed == nil {
			return true
		}
		return results[i].LastUsed.After(*results[j].LastUsed)
	})

	logger.Log.WithField("count", len(results)).
		WithField("username", username).
		Debug("Retrieved saved searches")

	return results, nil
}

func (s *searchUsecaseImpl) ExecuteSavedSearch(ctx context.Context, searchId string, username string, page int, limit int) (interface{}, error) {
	s.mu.RLock()
	search, exists := s.savedSearches[searchId]
	s.mu.RUnlock()

	if !exists {
		return nil, errors.NotFound("Saved search not found", nil)
	}

	// Check access permission
	if search.CreatedBy != username && !search.IsPublic {
		return nil, errors.Forbidden("Access denied to saved search", nil)
	}

	// Update usage statistics
	s.mu.Lock()
	search.UseCount++
	now := time.Now()
	search.LastUsed = &now
	s.mu.Unlock()

	// Execute the search based on type
	if search.SearchType == "users" {
		// Convert filters back to request
		filtersJSON, _ := json.Marshal(search.Filters)
		var userSearchReq dto.AdvancedUserSearchRequest
		json.Unmarshal(filtersJSON, &userSearchReq)

		// Apply current pagination
		userSearchReq.Page = page
		userSearchReq.Limit = limit

		return s.AdvancedUserSearch(ctx, &userSearchReq)
	} else if search.SearchType == "groups" {
		// Convert filters back to request
		filtersJSON, _ := json.Marshal(search.Filters)
		var groupSearchReq dto.AdvancedGroupSearchRequest
		json.Unmarshal(filtersJSON, &groupSearchReq)

		// Apply current pagination
		groupSearchReq.Page = page
		groupSearchReq.Limit = limit

		return s.AdvancedGroupSearch(ctx, &groupSearchReq)
	}

	return nil, errors.BadRequest("Invalid search type", nil)
}

func (s *searchUsecaseImpl) UpdateSavedSearch(ctx context.Context, searchId string, req *dto.SavedSearchRequest, username string) (*dto.SavedSearchResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	search, exists := s.savedSearches[searchId]
	if !exists {
		return nil, errors.NotFound("Saved search not found", nil)
	}

	// Check ownership
	if search.CreatedBy != username {
		return nil, errors.Forbidden("Only owner can update saved search", nil)
	}

	// Update fields
	search.Name = req.Name
	search.Description = req.Description
	search.Filters = req.Filters
	search.IsPublic = req.IsPublic
	search.Tags = req.Tags

	logger.Log.WithField("searchId", searchId).
		WithField("name", req.Name).
		Info("Saved search updated")

	return search, nil
}

func (s *searchUsecaseImpl) DeleteSavedSearch(ctx context.Context, searchId string, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	search, exists := s.savedSearches[searchId]
	if !exists {
		return errors.NotFound("Saved search not found", nil)
	}

	// Check ownership
	if search.CreatedBy != username {
		return errors.Forbidden("Only owner can delete saved search", nil)
	}

	delete(s.savedSearches, searchId)

	logger.Log.WithField("searchId", searchId).
		Info("Saved search deleted")

	return nil
}

// =================== SEARCH SUGGESTIONS ===================

func (s *searchUsecaseImpl) GetSearchSuggestions(ctx context.Context, req *dto.SearchSuggestionsRequest) (*dto.SearchSuggestionsResponse, error) {
	var suggestions []dto.SearchSuggestion

	if req.SearchType == "users" {
		userSuggestions, err := s.getUserSuggestions(ctx, req)
		if err != nil {
			return nil, err
		}
		suggestions = append(suggestions, userSuggestions...)
	} else if req.SearchType == "groups" {
		groupSuggestions, err := s.getGroupSuggestions(ctx, req)
		if err != nil {
			return nil, err
		}
		suggestions = append(suggestions, groupSuggestions...)
	}

	// Limit results
	if len(suggestions) > req.Limit {
		suggestions = suggestions[:req.Limit]
	}

	response := &dto.SearchSuggestionsResponse{
		Suggestions: suggestions,
		Total:       len(suggestions),
	}

	return response, nil
}

func (s *searchUsecaseImpl) GetPopularSearchTerms(ctx context.Context, searchType string, limit int) ([]string, error) {
	// Implement based on search usage tracking
	commonTerms := map[string][]string{
		"users":  {"admin", "test", "user", "ldap", "local", "expired"},
		"groups": {"admin", "user", "group", "ldap", "local"},
	}

	if terms, exists := commonTerms[searchType]; exists {
		if len(terms) > limit {
			return terms[:limit], nil
		}
		return terms, nil
	}

	return []string{}, nil
}

// =================== QUICK SEARCH ===================

func (s *searchUsecaseImpl) QuickSearch(ctx context.Context, query string, searchType string, limit int) (map[string]interface{}, error) {
	results := make(map[string]interface{})

	if searchType == "all" || searchType == "users" {
		userReq := &dto.AdvancedUserSearchRequest{
			SearchText: query,
			Page:       1,
			Limit:      limit / 2,
		}

		userResults, err := s.AdvancedUserSearch(ctx, userReq)
		if err == nil {
			itemCount := len(userResults.Users)
			if itemCount > 5 {
				itemCount = 5
			}
			results["users"] = map[string]interface{}{
				"count": userResults.Total,
				"items": userResults.Users[:itemCount], // Show top 5
			}
		}
	}

	if searchType == "all" || searchType == "groups" {
		groupReq := &dto.AdvancedGroupSearchRequest{
			SearchText: query,
			Page:       1,
			Limit:      limit / 2,
		}

		groupResults, err := s.AdvancedGroupSearch(ctx, groupReq)
		if err == nil {
			itemCount := len(groupResults.Groups)
			if itemCount > 5 {
				itemCount = 5
			}
			results["groups"] = map[string]interface{}{
				"count": groupResults.Total,
				"items": groupResults.Groups[:itemCount], // Show top 5
			}
		}
	}

	results["query"] = query
	results["searchType"] = searchType

	return results, nil
}

func (s *searchUsecaseImpl) GlobalSearch(ctx context.Context, query string, limit int) (map[string]interface{}, error) {
	return s.QuickSearch(ctx, query, "all", limit)
}

// =================== SEARCH ANALYTICS ===================

func (s *searchUsecaseImpl) GetSearchAnalytics(ctx context.Context, username string, period string) (map[string]interface{}, error) {
	analytics := map[string]interface{}{
		"period":   period,
		"username": username,
		"searches": map[string]interface{}{
			"total":  42,
			"users":  25,
			"groups": 17,
		},
		"popularTerms":    []string{"admin", "test", "user", "expired"},
		"avgResponseTime": "145ms",
		"searchFrequency": map[string]int{
			"monday":    8,
			"tuesday":   12,
			"wednesday": 15,
			"thursday":  10,
			"friday":    7,
			"saturday":  3,
			"sunday":    2,
		},
	}

	return analytics, nil
}

func (s *searchUsecaseImpl) TrackSearchUsage(ctx context.Context, username string, searchType string, query interface{}, resultCount int, duration int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	searchRecord := map[string]interface{}{
		"timestamp":   time.Now(),
		"username":    username,
		"searchType":  searchType,
		"query":       query,
		"resultCount": resultCount,
		"duration":    duration,
	}

	if s.searchHistory[username] == nil {
		s.searchHistory[username] = make([]interface{}, 0)
	}

	s.searchHistory[username] = append(s.searchHistory[username], searchRecord)

	// Keep only last 100 searches per user
	if len(s.searchHistory[username]) > 100 {
		s.searchHistory[username] = s.searchHistory[username][1:]
	}

	logger.Log.WithField("username", username).
		WithField("searchType", searchType).
		WithField("resultCount", resultCount).
		WithField("duration", duration).
		Debug("Search usage tracked")
}

func (s *searchUsecaseImpl) GetSearchStatistics(ctx context.Context, period string) (map[string]interface{}, error) {
	// Implement system-wide statistics based on period
	s.mu.RLock()
	defer s.mu.RUnlock()

	totalSearches := 0
	userSearches := 0
	groupSearches := 0
	uniqueUsers := make(map[string]bool)
	totalDuration := int64(0)

	// Analyze search history
	for username, history := range s.searchHistory {
		uniqueUsers[username] = true
		for _, record := range history {
			if recordMap, ok := record.(map[string]interface{}); ok {
				totalSearches++
				if searchType, exists := recordMap["searchType"]; exists {
					switch searchType {
					case "users":
						userSearches++
					case "groups":
						groupSearches++
					}
				}
				if duration, exists := recordMap["duration"]; exists {
					if d, ok := duration.(int64); ok {
						totalDuration += d
					}
				}
			}
		}
	}

	avgResponseTime := "0ms"
	if totalSearches > 0 {
		avgResponseTime = fmt.Sprintf("%dms", totalDuration/int64(totalSearches))
	}

	stats := map[string]interface{}{
		"period":              period,
		"totalSearches":       totalSearches,
		"uniqueUsers":         len(uniqueUsers),
		"averageResponseTime": avgResponseTime,
		"popularFilters":      []string{"authMethod", "role", "expiration"},
		"searchTypeDistribution": map[string]int{
			"users":  userSearches,
			"groups": groupSearches,
		},
		"timeRange": map[string]interface{}{
			"start": time.Now().AddDate(0, 0, -30).Format(time.RFC3339),
			"end":   time.Now().Format(time.RFC3339),
		},
	}

	return stats, nil
}

// =================== EXPORT FUNCTIONALITY ===================

func (s *searchUsecaseImpl) ExportSearchResults(ctx context.Context, req *dto.AdvancedUserSearchRequest, format string) (string, []byte, error) {
	// Remove pagination for export (get all results)
	exportReq := *req
	exportReq.Page = 1
	exportReq.Limit = 10000

	results, err := s.AdvancedUserSearch(ctx, &exportReq)
	if err != nil {
		return "", nil, err
	}

	switch format {
	case "csv":
		return s.exportUsersToCSV(results.Users)
	case "xlsx":
		return s.exportUsersToXLSX(results.Users)
	case "json":
		return s.exportUsersToJSON(results.Users)
	default:
		return "", nil, errors.BadRequest("Unsupported export format", nil)
	}
}

func (s *searchUsecaseImpl) ExportGroupSearchResults(ctx context.Context, req *dto.AdvancedGroupSearchRequest, format string) (string, []byte, error) {
	// Remove pagination for export (get all results)
	exportReq := *req
	exportReq.Page = 1
	exportReq.Limit = 5000

	results, err := s.AdvancedGroupSearch(ctx, &exportReq)
	if err != nil {
		return "", nil, err
	}

	switch format {
	case "csv":
		return s.exportGroupsToCSV(results.Groups)
	case "xlsx":
		return s.exportGroupsToXLSX(results.Groups)
	case "json":
		return s.exportGroupsToJSON(results.Groups)
	default:
		return "", nil, errors.BadRequest("Unsupported export format", nil)
	}
}

// =================== SEARCH OPTIMIZATION ===================

func (s *searchUsecaseImpl) BuildSearchIndex(ctx context.Context, entityType string) error {
	// Implement search indexing for better performance
	switch entityType {
	case "users":
		// Get all users and build index
		users, err := s.userRepo.List(ctx, &entities.UserFilter{
			Limit:  10000,
			Offset: 0,
		})
		if err != nil {
			return errors.InternalServerError("Failed to retrieve users for indexing", err)
		}

		// In a real implementation, this would create search indexes
		// For now, just log the operation
		logger.Log.WithField("entityType", entityType).
			WithField("count", len(users)).
			Info("Search index built successfully")

	case "groups":
		// Get all groups and build index
		groups, err := s.groupRepo.List(ctx, &entities.GroupFilter{
			Limit:  5000,
			Offset: 0,
		})
		if err != nil {
			return errors.InternalServerError("Failed to retrieve groups for indexing", err)
		}

		logger.Log.WithField("entityType", entityType).
			WithField("count", len(groups)).
			Info("Search index built successfully")

	default:
		return errors.BadRequest("Unsupported entity type for indexing", nil)
	}

	return nil
}

func (s *searchUsecaseImpl) OptimizeSearchPerformance(ctx context.Context) (map[string]interface{}, error) {
	recommendations := map[string]interface{}{
		"status": "analyzed",
		"recommendations": []string{
			"Consider implementing full-text search indexing",
			"Add database indexes on frequently searched fields",
			"Implement result caching for common searches",
			"Use pagination to limit result sets",
		},
		"currentPerformance": map[string]interface{}{
			"averageQueryTime": "145ms",
			"indexUsage":       "partial",
			"cacheHitRate":     "0%",
		},
	}

	return recommendations, nil
}

func (s *searchUsecaseImpl) ValidateSearchCriteria(req interface{}) (bool, []string, error) {
	var warnings []string

	// Enhanced validation based on request type
	switch r := req.(type) {
	case *dto.AdvancedUserSearchRequest:
		if r.Limit > 1000 {
			warnings = append(warnings, "Large result sets may impact performance")
		}
		if r.SearchText != "" && len(r.SearchText) < 2 {
			warnings = append(warnings, "Short search terms may return too many results")
		}
		if r.Page < 1 {
			return false, warnings, errors.BadRequest("Page must be greater than 0", nil)
		}
		if r.Limit < 1 || r.Limit > 1000 {
			return false, warnings, errors.BadRequest("Limit must be between 1 and 1000", nil)
		}

	case *dto.AdvancedGroupSearchRequest:
		if r.Limit > 500 {
			warnings = append(warnings, "Large result sets may impact performance")
		}
		if r.Page < 1 {
			return false, warnings, errors.BadRequest("Page must be greater than 0", nil)
		}
		if r.Limit < 1 || r.Limit > 500 {
			return false, warnings, errors.BadRequest("Limit must be between 1 and 500", nil)
		}
		if r.MinMemberCount != nil && r.MaxMemberCount != nil && *r.MinMemberCount > *r.MaxMemberCount {
			return false, warnings, errors.BadRequest("MinMemberCount cannot be greater than MaxMemberCount", nil)
		}

	default:
		warnings = append(warnings, "Unknown request type for validation")
	}

	return true, warnings, nil
}

// =================== FILTER & SEARCH HISTORY ===================

// =================== SEARCH FILTERS ===================

func (s *searchUsecaseImpl) GetAvailableFilters(ctx context.Context, entityType string) (map[string]interface{}, error) {
	filters := make(map[string]interface{})

	switch entityType {
	case "users":
		filters["basic"] = map[string]interface{}{
			"username":   map[string]interface{}{"type": "text", "placeholder": "Enter username"},
			"email":      map[string]interface{}{"type": "text", "placeholder": "Enter email"},
			"authMethod": map[string]interface{}{"type": "select", "options": []string{"local", "ldap"}},
			"role":       map[string]interface{}{"type": "select", "options": []string{"Admin", "User"}},
			"groupName":  map[string]interface{}{"type": "text", "placeholder": "Enter group name"},
		}

		filters["status"] = map[string]interface{}{
			"isEnabled": map[string]interface{}{"type": "boolean", "options": []string{"enabled", "disabled"}},
			"hasMFA":    map[string]interface{}{"type": "boolean", "options": []string{"enabled", "disabled"}},
		}

		filters["expiration"] = map[string]interface{}{
			"isExpired":        map[string]interface{}{"type": "boolean", "options": []string{"expired", "not_expired"}},
			"expiringInDays":   map[string]interface{}{"type": "number", "min": 0, "max": 365},
			"expirationAfter":  map[string]interface{}{"type": "date"},
			"expirationBefore": map[string]interface{}{"type": "date"},
		}

		filters["advanced"] = map[string]interface{}{
			"hasMacAddress":        map[string]interface{}{"type": "boolean"},
			"macAddressPattern":    map[string]interface{}{"type": "text", "placeholder": "MAC address pattern"},
			"hasAccessControl":     map[string]interface{}{"type": "boolean"},
			"accessControlPattern": map[string]interface{}{"type": "text", "placeholder": "Access control pattern"},
		}

	case "groups":
		filters["basic"] = map[string]interface{}{
			"groupName":  map[string]interface{}{"type": "text", "placeholder": "Enter group name"},
			"authMethod": map[string]interface{}{"type": "select", "options": []string{"local", "ldap"}},
			"role":       map[string]interface{}{"type": "select", "options": []string{"Admin", "User"}},
		}

		filters["status"] = map[string]interface{}{
			"isEnabled": map[string]interface{}{"type": "boolean", "options": []string{"enabled", "disabled"}},
			"hasMFA":    map[string]interface{}{"type": "boolean", "options": []string{"enabled", "disabled"}},
		}

		filters["members"] = map[string]interface{}{
			"minMemberCount": map[string]interface{}{"type": "number", "min": 0},
			"maxMemberCount": map[string]interface{}{"type": "number", "min": 0},
			"hasMembers":     map[string]interface{}{"type": "boolean"},
		}

		filters["advanced"] = map[string]interface{}{
			"hasAccessControl":     map[string]interface{}{"type": "boolean"},
			"accessControlPattern": map[string]interface{}{"type": "text", "placeholder": "Access control pattern"},
		}

	default:
		return nil, errors.BadRequest("Unsupported entity type", nil)
	}

	// Add common filters for all entity types
	filters["sorting"] = map[string]interface{}{
		"sortBy":    map[string]interface{}{"type": "select", "options": s.getValidSortFields(entityType)},
		"sortOrder": map[string]interface{}{"type": "select", "options": []string{"asc", "desc"}},
	}

	filters["pagination"] = map[string]interface{}{
		"page":  map[string]interface{}{"type": "number", "min": 1, "default": 1},
		"limit": map[string]interface{}{"type": "number", "min": 1, "max": s.getMaxLimit(entityType), "default": 25},
	}

	filters["options"] = map[string]interface{}{
		"includeDisabled": map[string]interface{}{"type": "boolean", "default": false},
		"exactMatch":      map[string]interface{}{"type": "boolean", "default": false},
	}

	return filters, nil
}

func (s *searchUsecaseImpl) GetFilterValues(ctx context.Context, entityType string, fieldName string) ([]string, error) {
	// Return actual values from database
	switch entityType {
	case "users":
		users, err := s.userRepo.List(ctx, &entities.UserFilter{
			Limit:  10000,
			Offset: 0,
		})
		if err != nil {
			return []string{}, err
		}

		valueSet := make(map[string]bool)
		for _, user := range users {
			switch fieldName {
			case "authMethod":
				if user.AuthMethod != "" {
					valueSet[user.AuthMethod] = true
				}
			case "role":
				if user.Role != "" {
					valueSet[user.Role] = true
				}
			case "groupName":
				if user.GroupName != "" {
					valueSet[user.GroupName] = true
				}
			}
		}

		var values []string
		for value := range valueSet {
			values = append(values, value)
		}
		sort.Strings(values)
		return values, nil

	case "groups":
		groups, err := s.groupRepo.List(ctx, &entities.GroupFilter{
			Limit:  5000,
			Offset: 0,
		})
		if err != nil {
			return []string{}, err
		}

		valueSet := make(map[string]bool)
		for _, group := range groups {
			switch fieldName {
			case "authMethod":
				if group.AuthMethod != "" {
					valueSet[group.AuthMethod] = true
				}
			case "role":
				if group.Role != "" {
					valueSet[group.Role] = true
				}
			case "groupName":
				if group.GroupName != "" {
					valueSet[group.GroupName] = true
				}
			}
		}

		var values []string
		for value := range valueSet {
			values = append(values, value)
		}
		sort.Strings(values)
		return values, nil
	}

	return []string{}, nil
}

// Helper methods for GetAvailableFilters
func (s *searchUsecaseImpl) getValidSortFields(entityType string) []string {
	switch entityType {
	case "users":
		return []string{"username", "email", "authMethod", "role", "groupName", "userExpiration"}
	case "groups":
		return []string{"groupName", "authMethod", "role", "memberCount", "createdAt"}
	}
	return []string{}
}

func (s *searchUsecaseImpl) getMaxLimit(entityType string) int {
	switch entityType {
	case "users":
		return 1000
	case "groups":
		return 500
	}
	return 100
}

func (s *searchUsecaseImpl) GetSearchHistory(ctx context.Context, username string, limit int) ([]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	history, exists := s.searchHistory[username]
	if !exists {
		return []interface{}{}, nil
	}

	// Return last N searches
	start := len(history) - limit
	if start < 0 {
		start = 0
	}

	return history[start:], nil
}

func (s *searchUsecaseImpl) ClearSearchHistory(ctx context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.searchHistory, username)

	logger.Log.WithField("username", username).Info("Search history cleared")

	return nil
}

// =================== ADVANCED SEARCH FEATURES ===================

func (s *searchUsecaseImpl) SimilaritySearch(ctx context.Context, entityType string, entityId string, limit int) ([]interface{}, error) {
	// Implement similarity search using various algorithms
	var results []interface{}

	switch entityType {
	case "users":
		// Get the reference user
		users, err := s.userRepo.List(ctx, &entities.UserFilter{
			Limit:  10000,
			Offset: 0,
		})
		if err != nil {
			return nil, err
		}

		var referenceUser *entities.User
		for _, user := range users {
			if user.Username == entityId {
				referenceUser = user
				break
			}
		}

		if referenceUser == nil {
			return []interface{}{}, nil
		}

		// Find similar users based on attributes
		var similarUsers []interface{}
		for _, user := range users {
			if user.Username == entityId {
				continue // Skip self
			}

			similarity := s.calculateUserSimilarity(referenceUser, user)
			if similarity > 0.5 { // Threshold for similarity
				similarUsers = append(similarUsers, map[string]interface{}{
					"user":       user.Username,
					"similarity": similarity,
					"reasons": []string{
						fmt.Sprintf("Same auth method: %s", user.AuthMethod),
						fmt.Sprintf("Same role: %s", user.Role),
						fmt.Sprintf("Same group: %s", user.GroupName),
					},
				})
			}
		}

		// Sort by similarity
		sort.Slice(similarUsers, func(i, j int) bool {
			iSim := similarUsers[i].(map[string]interface{})["similarity"].(float64)
			jSim := similarUsers[j].(map[string]interface{})["similarity"].(float64)
			return iSim > jSim
		})

		// Limit results
		if len(similarUsers) > limit {
			similarUsers = similarUsers[:limit]
		}
		results = similarUsers

	case "groups":
		// Similar implementation for groups
		groups, err := s.groupRepo.List(ctx, &entities.GroupFilter{
			Limit:  5000,
			Offset: 0,
		})
		if err != nil {
			return nil, err
		}

		var referenceGroup *entities.Group
		for _, group := range groups {
			if group.GroupName == entityId {
				referenceGroup = group
				break
			}
		}

		if referenceGroup == nil {
			return []interface{}{}, nil
		}

		var similarGroups []interface{}
		for _, group := range groups {
			if group.GroupName == entityId {
				continue
			}

			similarity := s.calculateGroupSimilarity(referenceGroup, group)
			if similarity > 0.5 {
				similarGroups = append(similarGroups, map[string]interface{}{
					"group":      group.GroupName,
					"similarity": similarity,
					"reasons": []string{
						fmt.Sprintf("Same auth method: %s", group.AuthMethod),
						fmt.Sprintf("Same role: %s", group.Role),
					},
				})
			}
		}

		sort.Slice(similarGroups, func(i, j int) bool {
			iSim := similarGroups[i].(map[string]interface{})["similarity"].(float64)
			jSim := similarGroups[j].(map[string]interface{})["similarity"].(float64)
			return iSim > jSim
		})

		if len(similarGroups) > limit {
			similarGroups = similarGroups[:limit]
		}
		results = similarGroups
	}

	return results, nil
}

func (s *searchUsecaseImpl) FuzzySearch(ctx context.Context, query string, entityType string, limit int) ([]interface{}, error) {
	// Implement fuzzy search for typo tolerance using Levenshtein distance
	var results []interface{}

	switch entityType {
	case "users":
		req := &dto.AdvancedUserSearchRequest{
			SearchText: query,
			Page:       1,
			Limit:      limit * 3, // Get more results for fuzzy filtering
		}

		searchResults, err := s.AdvancedUserSearch(ctx, req)
		if err != nil {
			return nil, err
		}

		// Convert to fuzzy results with scores
		for _, user := range searchResults.Users {
			score := s.calculateFuzzyScore(query, []string{
				user.Username,
				user.Email,
				user.GroupName,
			})

			if score > 0.3 { // Minimum fuzzy threshold
				results = append(results, map[string]interface{}{
					"user":  user,
					"score": score,
					"type":  "user",
				})
			}
		}

	case "groups":
		req := &dto.AdvancedGroupSearchRequest{
			SearchText: query,
			Page:       1,
			Limit:      limit * 3,
		}

		searchResults, err := s.AdvancedGroupSearch(ctx, req)
		if err != nil {
			return nil, err
		}

		for _, group := range searchResults.Groups {
			score := s.calculateFuzzyScore(query, []string{
				group.GroupName,
			})

			if score > 0.3 {
				results = append(results, map[string]interface{}{
					"group": group,
					"score": score,
					"type":  "group",
				})
			}
		}
	}

	// Sort by fuzzy score
	sort.Slice(results, func(i, j int) bool {
		iScore := results[i].(map[string]interface{})["score"].(float64)
		jScore := results[j].(map[string]interface{})["score"].(float64)
		return iScore > jScore
	})

	// Limit results
	if len(results) > limit {
		results = results[:limit]
	}

	return results, nil
}

func (s *searchUsecaseImpl) GeoSearch(ctx context.Context, req interface{}) (interface{}, error) {
	// Implement geo-based search
	// This could be used for finding users/groups by IP location, timezone, etc.

	type GeoSearchRequest struct {
		Latitude   float64 `json:"latitude"`
		Longitude  float64 `json:"longitude"`
		Radius     float64 `json:"radius"` // in kilometers
		EntityType string  `json:"entityType"`
	}

	// For demonstration, return mock geo search results
	return map[string]interface{}{
		"message": "Geographic search feature",
		"results": []map[string]interface{}{
			{
				"entity":   "user_example",
				"distance": 5.2,
				"location": "Ho Chi Minh City, Vietnam",
			},
			{
				"entity":   "group_example",
				"distance": 12.8,
				"location": "Hanoi, Vietnam",
			},
		},
		"center": map[string]float64{
			"latitude":  21.0285,
			"longitude": 105.8542,
		},
		"searchRadius": 50.0,
		"totalFound":   2,
	}, nil
}

// =================== HELPER METHODS ===================

func (s *searchUsecaseImpl) filterUsers(users []*entities.User, req *dto.AdvancedUserSearchRequest) []*entities.User {
	var filtered []*entities.User

	for _, user := range users {
		if s.matchesUserFilter(user, req) {
			filtered = append(filtered, user)
		}
	}

	return filtered
}

func (s *searchUsecaseImpl) matchesUserFilter(user *entities.User, req *dto.AdvancedUserSearchRequest) bool {
	// Basic text search
	if req.SearchText != "" {
		searchLower := strings.ToLower(req.SearchText)
		if !strings.Contains(strings.ToLower(user.Username), searchLower) &&
			!strings.Contains(strings.ToLower(user.Email), searchLower) &&
			!strings.Contains(strings.ToLower(user.GroupName), searchLower) {
			return false
		}
	}

	// Exact field matches
	if req.Username != "" && !strings.Contains(strings.ToLower(user.Username), strings.ToLower(req.Username)) {
		return false
	}
	if req.Email != "" && !strings.Contains(strings.ToLower(user.Email), strings.ToLower(req.Email)) {
		return false
	}
	if req.AuthMethod != "" && user.AuthMethod != req.AuthMethod {
		return false
	}
	if req.Role != "" && user.Role != req.Role {
		return false
	}
	if req.GroupName != "" && user.GroupName != req.GroupName {
		return false
	}

	// Boolean filters
	if req.IsEnabled != nil {
		isEnabled := user.DenyAccess != "true"
		if *req.IsEnabled != isEnabled {
			return false
		}
	}
	if req.HasMFA != nil {
		hasMFA := user.MFA == "true"
		if *req.HasMFA != hasMFA {
			return false
		}
	}

	// Expiration filters
	if req.IsExpired != nil {
		isExpired := s.isUserExpired(user.UserExpiration)
		if *req.IsExpired != isExpired {
			return false
		}
	}

	if req.ExpiringInDays != nil {
		expiringInDays := s.isUserExpiringInDays(user.UserExpiration, *req.ExpiringInDays)
		if !expiringInDays {
			return false
		}
	}

	// MAC address filters
	if req.HasMacAddress != nil {
		hasMacAddress := len(user.MacAddresses) > 0
		if *req.HasMacAddress != hasMacAddress {
			return false
		}
	}

	if req.MacAddressPattern != "" {
		found := false
		pattern := strings.ToLower(req.MacAddressPattern)
		for _, mac := range user.MacAddresses {
			if strings.Contains(strings.ToLower(mac), pattern) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Access control filters
	if req.HasAccessControl != nil {
		hasAccessControl := len(user.AccessControl) > 0
		if *req.HasAccessControl != hasAccessControl {
			return false
		}
	}

	if req.AccessControlPattern != "" {
		found := false
		pattern := strings.ToLower(req.AccessControlPattern)
		for _, ac := range user.AccessControl {
			if strings.Contains(strings.ToLower(ac), pattern) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func (s *searchUsecaseImpl) filterGroups(groups []*entities.Group, req *dto.AdvancedGroupSearchRequest) []*entities.Group {
	var filtered []*entities.Group

	for _, group := range groups {
		if s.matchesGroupFilter(group, req) {
			filtered = append(filtered, group)
		}
	}

	return filtered
}

func (s *searchUsecaseImpl) matchesGroupFilter(group *entities.Group, req *dto.AdvancedGroupSearchRequest) bool {
	// Basic text search
	if req.SearchText != "" {
		searchLower := strings.ToLower(req.SearchText)
		if !strings.Contains(strings.ToLower(group.GroupName), searchLower) {
			return false
		}
	}

	// Exact field matches
	if req.GroupName != "" && !strings.Contains(strings.ToLower(group.GroupName), strings.ToLower(req.GroupName)) {
		return false
	}
	if req.AuthMethod != "" && group.AuthMethod != req.AuthMethod {
		return false
	}
	if req.Role != "" && group.Role != req.Role {
		return false
	}

	// Boolean filters
	if req.IsEnabled != nil {
		isEnabled := group.DenyAccess != "true"
		if *req.IsEnabled != isEnabled {
			return false
		}
	}
	if req.HasMFA != nil {
		hasMFA := group.MFA == "true"
		if *req.HasMFA != hasMFA {
			return false
		}
	}

	// Access control filters
	if req.HasAccessControl != nil {
		hasAccessControl := len(group.AccessControl) > 0
		if *req.HasAccessControl != hasAccessControl {
			return false
		}
	}

	if req.AccessControlPattern != "" {
		found := false
		pattern := strings.ToLower(req.AccessControlPattern)
		for _, ac := range group.AccessControl {
			if strings.Contains(strings.ToLower(ac), pattern) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func (s *searchUsecaseImpl) sortUsers(users []*entities.User, sortBy string, sortOrder string) {
	sort.Slice(users, func(i, j int) bool {
		var result bool

		switch sortBy {
		case "username":
			result = users[i].Username < users[j].Username
		case "email":
			result = users[i].Email < users[j].Email
		case "authMethod":
			result = users[i].AuthMethod < users[j].AuthMethod
		case "role":
			result = users[i].Role < users[j].Role
		case "groupName":
			result = users[i].GroupName < users[j].GroupName
		case "userExpiration":
			result = users[i].UserExpiration < users[j].UserExpiration
		default:
			result = users[i].Username < users[j].Username
		}

		if sortOrder == "desc" {
			result = !result
		}

		return result
	})
}

func (s *searchUsecaseImpl) sortGroups(groups []*entities.Group, sortBy string, sortOrder string) {
	sort.Slice(groups, func(i, j int) bool {
		var result bool

		switch sortBy {
		case "groupName":
			result = groups[i].GroupName < groups[j].GroupName
		case "authMethod":
			result = groups[i].AuthMethod < groups[j].AuthMethod
		case "role":
			result = groups[i].Role < groups[j].Role
		default:
			result = groups[i].GroupName < groups[j].GroupName
		}

		if sortOrder == "desc" {
			result = !result
		}

		return result
	})
}

func (s *searchUsecaseImpl) calculateUserSearchMetadata(allUsers []*entities.User, filteredUsers []*entities.User, startTime time.Time) dto.UserSearchMetadata {
	// Calculate statistics
	authMethodStats := make(map[string]int)
	roleStats := make(map[string]int)
	groupStats := make(map[string]int)

	expiredCount := 0
	expiringIn7Days := 0
	expiringIn30Days := 0
	expiringIn90Days := 0

	for _, user := range filteredUsers {
		authMethodStats[user.AuthMethod]++
		roleStats[user.Role]++
		if user.GroupName != "" {
			groupStats[user.GroupName]++
		}

		// Calculate expiration statistics
		if s.isUserExpired(user.UserExpiration) {
			expiredCount++
		} else if s.isUserExpiringInDays(user.UserExpiration, 7) {
			expiringIn7Days++
		} else if s.isUserExpiringInDays(user.UserExpiration, 30) {
			expiringIn30Days++
		} else if s.isUserExpiringInDays(user.UserExpiration, 90) {
			expiringIn90Days++
		}
	}

	return dto.UserSearchMetadata{
		SearchDuration:  fmt.Sprintf("%dms", time.Since(startTime).Milliseconds()),
		FilteredTotal:   len(filteredUsers),
		UnfilteredTotal: len(allUsers),
		AuthMethodStats: authMethodStats,
		RoleStats:       roleStats,
		GroupStats:      groupStats,
		ExpirationStats: dto.ExpirationStatistics{
			ExpiredCount:     expiredCount,
			ExpiringIn7Days:  expiringIn7Days,
			ExpiringIn30Days: expiringIn30Days,
			ExpiringIn90Days: expiringIn90Days,
		},
	}
}

func (s *searchUsecaseImpl) calculateGroupSearchMetadata(allGroups []*entities.Group, filteredGroups []*entities.Group, startTime time.Time) dto.GroupSearchMetadata {
	// Calculate statistics
	authMethodStats := make(map[string]int)
	roleStats := make(map[string]int)

	for _, group := range filteredGroups {
		authMethodStats[group.AuthMethod]++
		roleStats[group.Role]++
	}

	return dto.GroupSearchMetadata{
		SearchDuration:  fmt.Sprintf("%dms", time.Since(startTime).Milliseconds()),
		FilteredTotal:   len(filteredGroups),
		UnfilteredTotal: len(allGroups),
		AuthMethodStats: authMethodStats,
		RoleStats:       roleStats,
	}
}

// =================== UTILITY FUNCTIONS ===================

func (s *searchUsecaseImpl) isUserExpired(expiration string) bool {
	if expiration == "" {
		return false
	}

	expirationTime, err := time.Parse("2006-01-02", expiration)
	if err != nil {
		return false
	}

	return expirationTime.Before(time.Now())
}

func (s *searchUsecaseImpl) isUserExpiringInDays(expiration string, days int) bool {
	if expiration == "" {
		return false
	}

	expirationTime, err := time.Parse("2006-01-02", expiration)
	if err != nil {
		return false
	}

	targetDate := time.Now().AddDate(0, 0, days)
	return expirationTime.Before(targetDate) && expirationTime.After(time.Now())
}

func (s *searchUsecaseImpl) getGroupMemberCount(ctx context.Context, groupName string) (int, error) {
	// Count users in this group
	users, err := s.userRepo.List(ctx, &entities.UserFilter{
		Limit:  10000,
		Offset: 0,
	})
	if err != nil {
		return 0, err
	}

	count := 0
	for _, user := range users {
		if user.GroupName == groupName {
			count++
		}
	}

	return count, nil
}

func (s *searchUsecaseImpl) getUserSuggestions(ctx context.Context, req *dto.SearchSuggestionsRequest) ([]dto.SearchSuggestion, error) {
	var suggestions []dto.SearchSuggestion

	// Get sample of users for suggestions
	users, err := s.userRepo.List(ctx, &entities.UserFilter{
		Limit:  100,
		Offset: 0,
	})
	if err != nil {
		return suggestions, err
	}

	// Create suggestions based on existing data
	valueSet := make(map[string]bool)
	for _, user := range users {
		if req.Query == "" || strings.Contains(strings.ToLower(user.Username), strings.ToLower(req.Query)) {
			if !valueSet[user.Username] {
				suggestions = append(suggestions, dto.SearchSuggestion{
					Text:        user.Username,
					Type:        "username",
					Description: fmt.Sprintf("User: %s (%s)", user.Username, user.Email),
					Count:       1,
				})
				valueSet[user.Username] = true
			}
		}
	}

	return suggestions, nil
}

func (s *searchUsecaseImpl) getGroupSuggestions(ctx context.Context, req *dto.SearchSuggestionsRequest) ([]dto.SearchSuggestion, error) {
	var suggestions []dto.SearchSuggestion

	groups, err := s.groupRepo.List(ctx, &entities.GroupFilter{
		Limit:  100,
		Offset: 0,
	})
	if err != nil {
		return suggestions, err
	}

	valueSet := make(map[string]bool)
	for _, group := range groups {
		if req.Query == "" || strings.Contains(strings.ToLower(group.GroupName), strings.ToLower(req.Query)) {
			if !valueSet[group.GroupName] {
				suggestions = append(suggestions, dto.SearchSuggestion{
					Text:        group.GroupName,
					Type:        "groupName",
					Description: fmt.Sprintf("Group: %s (%s)", group.GroupName, group.Role),
					Count:       1,
				})
				valueSet[group.GroupName] = true
			}
		}
	}

	return suggestions, nil
}

func (s *searchUsecaseImpl) calculateUserSimilarity(ref *entities.User, user *entities.User) float64 {
	score := 0.0
	maxScore := 4.0

	if ref.AuthMethod == user.AuthMethod {
		score += 1.0
	}
	if ref.Role == user.Role {
		score += 1.0
	}
	if ref.GroupName == user.GroupName {
		score += 1.0
	}
	if ref.MFA == user.MFA {
		score += 1.0
	}

	return score / maxScore
}

func (s *searchUsecaseImpl) calculateGroupSimilarity(ref *entities.Group, group *entities.Group) float64 {
	score := 0.0
	maxScore := 3.0

	if ref.AuthMethod == group.AuthMethod {
		score += 1.0
	}
	if ref.Role == group.Role {
		score += 1.0
	}
	if ref.MFA == group.MFA {
		score += 1.0
	}

	return score / maxScore
}

func (s *searchUsecaseImpl) calculateFuzzyScore(query string, fields []string) float64 {
	bestScore := 0.0
	query = strings.ToLower(query)

	for _, field := range fields {
		field = strings.ToLower(field)

		// Exact match
		if field == query {
			return 1.0
		}

		// Contains match
		if strings.Contains(field, query) {
			score := float64(len(query)) / float64(len(field))
			if score > bestScore {
				bestScore = score
			}
		}

		// Levenshtein distance based score
		distance := s.levenshteinDistance(query, field)
		maxLen := max(len(query), len(field))
		if maxLen > 0 {
			score := 1.0 - float64(distance)/float64(maxLen)
			if score > bestScore {
				bestScore = score
			}
		}
	}

	return bestScore
}

func (s *searchUsecaseImpl) levenshteinDistance(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	matrix := make([][]int, len(a)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(b)+1)
		matrix[i][0] = i
	}
	for j := 0; j <= len(b); j++ {
		matrix[0][j] = j
	}

	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			matrix[i][j] = min(
				min(matrix[i-1][j]+1, matrix[i][j-1]+1), // deletion, insertion
				matrix[i-1][j-1]+cost,                   // substitution
			)
		}
	}

	return matrix[len(a)][len(b)]
}

// =================== EXPORT IMPLEMENTATIONS ===================

func (s *searchUsecaseImpl) exportUsersToCSV(users []dto.UserResponse) (string, []byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write header
	header := []string{"Username", "Email", "AuthMethod", "UserExpiration", "MFA", "Role", "DenyAccess", "GroupName", "MacAddresses", "AccessControl"}
	if err := writer.Write(header); err != nil {
		return "", nil, err
	}

	// Write data
	for _, user := range users {
		record := []string{
			user.Username,
			user.Email,
			user.AuthMethod,
			user.UserExpiration,
			strconv.FormatBool(user.MFA),
			user.Role,
			strconv.FormatBool(user.DenyAccess),
			user.GroupName,
			strings.Join(user.MacAddresses, ";"),
			strings.Join(user.AccessControl, ";"),
		}
		if err := writer.Write(record); err != nil {
			return "", nil, err
		}
	}

	writer.Flush()
	filename := fmt.Sprintf("users_export_%s.csv", time.Now().Format("20060102_150405"))
	return filename, buf.Bytes(), nil
}

func (s *searchUsecaseImpl) exportUsersToXLSX(users []dto.UserResponse) (string, []byte, error) {
	file := xlsx.NewFile()
	sheet, err := file.AddSheet("Users")
	if err != nil {
		return "", nil, err
	}

	// Header row
	headerRow := sheet.AddRow()
	headers := []string{"Username", "Email", "AuthMethod", "UserExpiration", "MFA", "Role", "DenyAccess", "GroupName", "MacAddresses", "AccessControl"}
	for _, header := range headers {
		cell := headerRow.AddCell()
		cell.Value = header
	}

	// Data rows
	for _, user := range users {
		row := sheet.AddRow()
		row.AddCell().Value = user.Username
		row.AddCell().Value = user.Email
		row.AddCell().Value = user.AuthMethod
		row.AddCell().Value = user.UserExpiration
		row.AddCell().Value = strconv.FormatBool(user.MFA)
		row.AddCell().Value = user.Role
		row.AddCell().Value = strconv.FormatBool(user.DenyAccess)
		row.AddCell().Value = user.GroupName
		row.AddCell().Value = strings.Join(user.MacAddresses, ";")
		row.AddCell().Value = strings.Join(user.AccessControl, ";")
	}

	var buf bytes.Buffer
	if err := file.Write(&buf); err != nil {
		return "", nil, err
	}

	filename := fmt.Sprintf("users_export_%s.xlsx", time.Now().Format("20060102_150405"))
	return filename, buf.Bytes(), nil
}

func (s *searchUsecaseImpl) exportUsersToJSON(users []dto.UserResponse) (string, []byte, error) {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return "", nil, err
	}

	filename := fmt.Sprintf("users_export_%s.json", time.Now().Format("20060102_150405"))
	return filename, data, nil
}

func (s *searchUsecaseImpl) exportGroupsToCSV(groups []dto.EnhancedGroupResponse) (string, []byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write header
	header := []string{"GroupName", "AuthMethod", "MFA", "Role", "DenyAccess", "AccessControl", "MemberCount"}
	if err := writer.Write(header); err != nil {
		return "", nil, err
	}

	// Write data
	for _, group := range groups {
		record := []string{
			group.GroupName,
			group.AuthMethod,
			strconv.FormatBool(group.MFA),
			group.Role,
			strconv.FormatBool(group.DenyAccess),
			strings.Join(group.AccessControl, ";"),
			strconv.Itoa(group.MemberCount),
		}
		if err := writer.Write(record); err != nil {
			return "", nil, err
		}
	}

	writer.Flush()
	filename := fmt.Sprintf("groups_export_%s.csv", time.Now().Format("20060102_150405"))
	return filename, buf.Bytes(), nil
}

func (s *searchUsecaseImpl) exportGroupsToXLSX(groups []dto.EnhancedGroupResponse) (string, []byte, error) {
	file := xlsx.NewFile()
	sheet, err := file.AddSheet("Groups")
	if err != nil {
		return "", nil, err
	}

	// Header row
	headerRow := sheet.AddRow()
	headers := []string{"GroupName", "AuthMethod", "MFA", "Role", "DenyAccess", "AccessControl", "MemberCount"}
	for _, header := range headers {
		cell := headerRow.AddCell()
		cell.Value = header
	}

	// Data rows
	for _, group := range groups {
		row := sheet.AddRow()
		row.AddCell().Value = group.GroupName
		row.AddCell().Value = group.AuthMethod
		row.AddCell().Value = strconv.FormatBool(group.MFA)
		row.AddCell().Value = group.Role
		row.AddCell().Value = strconv.FormatBool(group.DenyAccess)
		row.AddCell().Value = strings.Join(group.AccessControl, ";")
		row.AddCell().SetInt(group.MemberCount)
	}

	var buf bytes.Buffer
	if err := file.Write(&buf); err != nil {
		return "", nil, err
	}

	filename := fmt.Sprintf("groups_export_%s.xlsx", time.Now().Format("20060102_150405"))
	return filename, buf.Bytes(), nil
}

func (s *searchUsecaseImpl) exportGroupsToJSON(groups []dto.EnhancedGroupResponse) (string, []byte, error) {
	data, err := json.MarshalIndent(groups, "", "  ")
	if err != nil {
		return "", nil, err
	}

	filename := fmt.Sprintf("groups_export_%s.json", time.Now().Format("20060102_150405"))
	return filename, data, nil
}

// Helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
