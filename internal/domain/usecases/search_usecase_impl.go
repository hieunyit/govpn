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
	s.mu.Lock()
	defer s.mu.Unlock()

	searchId := uuid.New().String()
	now := time.Now()

	savedSearch := &dto.SavedSearchResponse{
		ID:          searchId,
		Name:        req.Name,
		Description: req.Description,
		SearchType:  req.SearchType,
		Filters:     req.Filters,
		IsPublic:    req.IsPublic,
		Tags:        req.Tags,
		CreatedBy:   username,
		CreatedAt:   now,
		UseCount:    0,
	}

	s.savedSearches[searchId] = savedSearch

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
		if search.CreatedBy != username && (!includePublic || !search.IsPublic) {
			continue
		}

		// Filter by search type if specified
		if searchType != "" && search.SearchType != searchType {
			continue
		}

		results = append(results, *search)
	}

	// Sort by creation date (newest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].CreatedAt.After(results[j].CreatedAt)
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
	// TODO: Implement based on search usage tracking
	// For now, return some common terms
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
			results["users"] = map[string]interface{}{
				"count": userResults.Total,
				"items": userResults.Users[:min(len(userResults.Users), 5)], // Show top 5
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
			results["groups"] = map[string]interface{}{
				"count": groupResults.Total,
				"items": groupResults.Groups[:min(len(groupResults.Groups), 5)], // Show top 5
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
	// TODO: Implement system-wide statistics
	stats := map[string]interface{}{
		"period":              period,
		"totalSearches":       1234,
		"uniqueUsers":         45,
		"averageResponseTime": "152ms",
		"popularFilters":      []string{"authMethod", "role", "expiration"},
		"searchTypeDistribution": map[string]int{
			"users":  785,
			"groups": 449,
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
	// TODO: Implement search indexing for better performance
	logger.Log.WithField("entityType", entityType).Info("Search index build requested (not implemented)")
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

	// Basic validation examples
	switch r := req.(type) {
	case *dto.AdvancedUserSearchRequest:
		if r.Limit > 1000 {
			warnings = append(warnings, "Large result sets may impact performance")
		}
		if r.SearchText != "" && len(r.SearchText) < 2 {
			warnings = append(warnings, "Short search terms may return too many results")
		}
	case *dto.AdvancedGroupSearchRequest:
		if r.Limit > 500 {
			warnings = append(warnings, "Large result sets may impact performance")
		}
	}

	return true, warnings, nil
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

	totalMembers := 0
	emptyGroups := 0
	smallGroups := 0
	mediumGroups := 0
	largeGroups := 0
	maxSize := 0

	for _, group := range filteredGroups {
		authMethodStats[group.AuthMethod]++
		roleStats[group.Role]++

		// Mock member count calculation (in real implementation, query database)
		memberCount := len(group.GroupName) % 25 // Mock data
		totalMembers += memberCount

		if memberCount == 0 {
			emptyGroups++
		} else if memberCount <= 10 {
			smallGroups++
		} else if memberCount <= 50 {
			mediumGroups++
		} else {
			largeGroups++
		}

		if memberCount > maxSize {
			maxSize = memberCount
		}
	}

	averageSize := 0.0
	if len(filteredGroups) > 0 {
		averageSize = float64(totalMembers) / float64(len(filteredGroups))
	}

	return dto.GroupSearchMetadata{
		SearchDuration:  fmt.Sprintf("%dms", time.Since(startTime).Milliseconds()),
		FilteredTotal:   len(filteredGroups),
		UnfilteredTotal: len(allGroups),
		AuthMethodStats: authMethodStats,
		RoleStats:       roleStats,
		MemberCountStats: dto.MemberCountStatistics{
			EmptyGroups:  emptyGroups,
			SmallGroups:  smallGroups,
			MediumGroups: mediumGroups,
			LargeGroups:  largeGroups,
			AverageSize:  averageSize,
			MaxSize:      maxSize,
		},
	}
}

// =================== UTILITY FUNCTIONS ===================

func (s *searchUsecaseImpl) isUserExpired(expiration string) bool {
	if expiration == "" {
		return false
	}

	expirationDate, err := time.Parse("02/01/2006", expiration)
	if err != nil {
		return false
	}

	return expirationDate.Before(time.Now())
}

func (s *searchUsecaseImpl) isUserExpiringInDays(expiration string, days int) bool {
	if expiration == "" {
		return false
	}

	expirationDate, err := time.Parse("02/01/2006", expiration)
	if err != nil {
		return false
	}

	targetDate := time.Now().AddDate(0, 0, days)
	return expirationDate.Before(targetDate) && expirationDate.After(time.Now())
}

func (s *searchUsecaseImpl) getGroupMemberCount(ctx context.Context, groupName string) (int, error) {
	// In a real implementation, this would query the database for users in this group
	// For now, return a mock count
	return len(groupName) % 25, nil
}

func (s *searchUsecaseImpl) getUserSuggestions(ctx context.Context, req *dto.SearchSuggestionsRequest) ([]dto.SearchSuggestion, error) {
	// Get sample users for suggestions
	users, err := s.userRepo.List(ctx, &entities.UserFilter{
		Username: req.Query,
		Limit:    req.Limit * 2,
		Offset:   0,
	})
	if err != nil {
		return nil, err
	}

	var suggestions []dto.SearchSuggestion
	for _, user := range users {
		if len(suggestions) >= req.Limit {
			break
		}

		// Match based on field or general search
		if req.Field == "" || req.Field == "username" {
			if strings.Contains(strings.ToLower(user.Username), strings.ToLower(req.Query)) {
				suggestions = append(suggestions, dto.SearchSuggestion{
					Value:      user.Username,
					Label:      fmt.Sprintf("%s (%s)", user.Username, user.Email),
					Type:       "username",
					Metadata:   map[string]string{"authMethod": user.AuthMethod, "role": user.Role},
					MatchCount: 1,
				})
			}
		}

		if req.Field == "" || req.Field == "email" {
			if strings.Contains(strings.ToLower(user.Email), strings.ToLower(req.Query)) {
				suggestions = append(suggestions, dto.SearchSuggestion{
					Value:      user.Email,
					Label:      fmt.Sprintf("%s (%s)", user.Email, user.Username),
					Type:       "email",
					Metadata:   map[string]string{"authMethod": user.AuthMethod, "role": user.Role},
					MatchCount: 1,
				})
			}
		}
	}

	return suggestions, nil
}

func (s *searchUsecaseImpl) getGroupSuggestions(ctx context.Context, req *dto.SearchSuggestionsRequest) ([]dto.SearchSuggestion, error) {
	// Get sample groups for suggestions
	groups, err := s.groupRepo.List(ctx, &entities.GroupFilter{
		GroupName: req.Query,
		Limit:     req.Limit * 2,
		Offset:    0,
	})
	if err != nil {
		return nil, err
	}

	var suggestions []dto.SearchSuggestion
	for _, group := range groups {
		if len(suggestions) >= req.Limit {
			break
		}

		if req.Field == "" || req.Field == "groupName" {
			if strings.Contains(strings.ToLower(group.GroupName), strings.ToLower(req.Query)) {
				suggestions = append(suggestions, dto.SearchSuggestion{
					Value:      group.GroupName,
					Label:      fmt.Sprintf("%s (%s)", group.GroupName, group.AuthMethod),
					Type:       "groupName",
					Metadata:   map[string]string{"authMethod": group.AuthMethod, "role": group.Role},
					MatchCount: 1,
				})
			}
		}
	}

	return suggestions, nil
}

// =================== EXPORT HELPERS ===================

func (s *searchUsecaseImpl) exportUsersToCSV(users []dto.UserResponse) (string, []byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write headers
	headers := []string{
		"Username", "Email", "Auth Method", "Role", "Group Name",
		"User Expiration", "MFA Enabled", "Access Denied", "MAC Addresses", "Access Control",
	}
	writer.Write(headers)

	// Write data
	for _, user := range users {
		record := []string{
			user.Username,
			user.Email,
			user.AuthMethod,
			user.Role,
			user.GroupName,
			user.UserExpiration,
			strconv.FormatBool(user.MFA),
			strconv.FormatBool(user.DenyAccess),
			strings.Join(user.MacAddresses, ";"),
			strings.Join(user.AccessControl, ";"),
		}
		writer.Write(record)
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

	// Headers
	headers := []string{
		"Username", "Email", "Auth Method", "Role", "Group Name",
		"User Expiration", "MFA Enabled", "Access Denied", "MAC Addresses", "Access Control",
	}

	headerRow := sheet.AddRow()
	for _, header := range headers {
		cell := headerRow.AddCell()
		cell.Value = header
		cell.GetStyle().Font.Bold = true
	}

	// Data
	for _, user := range users {
		row := sheet.AddRow()
		row.AddCell().Value = user.Username
		row.AddCell().Value = user.Email
		row.AddCell().Value = user.AuthMethod
		row.AddCell().Value = user.Role
		row.AddCell().Value = user.GroupName
		row.AddCell().Value = user.UserExpiration
		row.AddCell().Value = strconv.FormatBool(user.MFA)
		row.AddCell().Value = strconv.FormatBool(user.DenyAccess)
		row.AddCell().Value = strings.Join(user.MacAddresses, ";")
		row.AddCell().Value = strings.Join(user.AccessControl, ";")
	}

	var buf bytes.Buffer
	err = file.Write(&buf)
	if err != nil {
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

	// Write headers
	headers := []string{
		"Group Name", "Auth Method", "Role", "MFA Enabled", "Access Denied",
		"Member Count", "Access Control",
	}
	writer.Write(headers)

	// Write data
	for _, group := range groups {
		record := []string{
			group.GroupName,
			group.AuthMethod,
			group.Role,
			strconv.FormatBool(group.MFA),
			strconv.FormatBool(group.DenyAccess),
			strconv.Itoa(group.MemberCount),
			strings.Join(group.AccessControl, ";"),
		}
		writer.Write(record)
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

	// Headers
	headers := []string{
		"Group Name", "Auth Method", "Role", "MFA Enabled", "Access Denied",
		"Member Count", "Access Control",
	}

	headerRow := sheet.AddRow()
	for _, header := range headers {
		cell := headerRow.AddCell()
		cell.Value = header
		cell.GetStyle().Font.Bold = true
	}

	// Data
	for _, group := range groups {
		row := sheet.AddRow()
		row.AddCell().Value = group.GroupName
		row.AddCell().Value = group.AuthMethod
		row.AddCell().Value = group.Role
		row.AddCell().Value = strconv.FormatBool(group.MFA)
		row.AddCell().Value = strconv.FormatBool(group.DenyAccess)
		row.AddCell().Value = strconv.Itoa(group.MemberCount)
		row.AddCell().Value = strings.Join(group.AccessControl, ";")
	}

	var buf bytes.Buffer
	err = file.Write(&buf)
	if err != nil {
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

// =================== ADDITIONAL FEATURES ===================

func (s *searchUsecaseImpl) GetAvailableFilters(ctx context.Context, entityType string) (map[string]interface{}, error) {
	filters := make(map[string]interface{})

	if entityType == "users" {
		filters["authMethod"] = []string{"local", "ldap"}
		filters["role"] = []string{"Admin", "User"}
		filters["status"] = []string{"enabled", "disabled"}
		filters["mfa"] = []string{"enabled", "disabled"}
		filters["expiration"] = []string{"expired", "expiring_soon", "valid"}
	} else if entityType == "groups" {
		filters["authMethod"] = []string{"local", "ldap"}
		filters["role"] = []string{"Admin", "User"}
		filters["status"] = []string{"enabled", "disabled"}
		filters["mfa"] = []string{"enabled", "disabled"}
		filters["memberCount"] = []string{"empty", "small", "medium", "large"}
	}

	return filters, nil
}

func (s *searchUsecaseImpl) GetFilterValues(ctx context.Context, entityType string, fieldName string) ([]string, error) {
	// Return sample values - in real implementation, query database for distinct values
	values := map[string]map[string][]string{
		"users": {
			"authMethod": {"local", "ldap"},
			"role":       {"Admin", "User"},
			"groupName":  {"ADMIN_GR", "USER_GR", "TEST_GR"},
		},
		"groups": {
			"authMethod": {"local", "ldap"},
			"role":       {"Admin", "User"},
			"groupName":  {"ADMIN_GROUP", "USER_GROUP", "TEST_GROUP"},
		},
	}

	if entityValues, exists := values[entityType]; exists {
		if fieldValues, exists := entityValues[fieldName]; exists {
			return fieldValues, nil
		}
	}

	return []string{}, nil
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

func (s *searchUsecaseImpl) SimilaritySearch(ctx context.Context, entityType string, entityId string, limit int) ([]interface{}, error) {
	// TODO: Implement similarity search using various algorithms
	// For now, return empty results
	return []interface{}{}, nil
}

func (s *searchUsecaseImpl) FuzzySearch(ctx context.Context, query string, entityType string, limit int) ([]interface{}, error) {
	// TODO: Implement fuzzy search for typo tolerance
	// For now, fall back to regular search
	if entityType == "users" {
		req := &dto.AdvancedUserSearchRequest{
			SearchText: query,
			Page:       1,
			Limit:      limit,
		}
		return s.AdvancedUserSearch(ctx, req)
	} else if entityType == "groups" {
		req := &dto.AdvancedGroupSearchRequest{
			SearchText: query,
			Page:       1,
			Limit:      limit,
		}
		return s.AdvancedGroupSearch(ctx, req)
	}

	return []interface{}{}, nil
}

func (s *searchUsecaseImpl) GeoSearch(ctx context.Context, req interface{}) (interface{}, error) {
	// TODO: Implement geo-based search
	return map[string]interface{}{
		"message": "Geographic search not implemented yet",
	}, nil
}

// Helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
