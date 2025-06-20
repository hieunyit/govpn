package handlers

import (
	"govpn/internal/application/dto"
	"govpn/internal/domain/usecases"
	"govpn/pkg/errors"
	"govpn/pkg/logger"
	"govpn/pkg/validator"
	nethttp "net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type SearchHandler struct {
	searchUsecase usecases.SearchUsecase
}

func NewSearchHandler(searchUsecase usecases.SearchUsecase) *SearchHandler {
	return &SearchHandler{
		searchUsecase: searchUsecase,
	}
}

// =================== ADVANCED SEARCH ===================

// AdvancedUserSearch godoc
// @Summary Advanced user search
// @Description Search users with complex filters and sorting
// @Tags Advanced Search
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body dto.AdvancedUserSearchRequest true "Advanced search criteria"
// @Success 200 {object} dto.AdvancedUserSearchResponse
// @Failure 400 {object} dto.ErrorResponse
// @Router /api/openvpn/search/users [post]
func (h *SearchHandler) AdvancedUserSearch(c *gin.Context) {
	var req dto.AdvancedUserSearchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind advanced user search request")
		RespondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Advanced user search request validation failed")
		RespondWithValidationError(c, err)
		return
	}

	// Set default pagination if not provided
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.Limit <= 0 {
		req.Limit = 50
	}

	// Set default sorting if not provided
	if req.SortBy == "" {
		req.SortBy = "username"
	}
	if req.SortOrder == "" {
		req.SortOrder = "asc"
	}

	logger.Log.WithField("searchText", req.SearchText).
		WithField("authMethod", req.AuthMethod).
		WithField("role", req.Role).
		WithField("page", req.Page).
		WithField("limit", req.Limit).
		Debug("Processing advanced user search")

	// Perform search
	response, err := h.searchUsecase.AdvancedUserSearch(c.Request.Context(), &req)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Advanced user search failed", err))
		}
		return
	}

	logger.Log.WithField("total", response.Total).
		WithField("returned", len(response.Users)).
		WithField("searchDuration", response.Metadata.SearchDuration).
		Info("Advanced user search completed")

	RespondWithSuccess(c, nethttp.StatusOK, response)
}

// AdvancedGroupSearch godoc
// @Summary Advanced group search
// @Description Search groups with complex filters and sorting
// @Tags Advanced Search
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body dto.AdvancedGroupSearchRequest true "Advanced search criteria"
// @Success 200 {object} dto.AdvancedGroupSearchResponse
// @Failure 400 {object} dto.ErrorResponse
// @Router /api/openvpn/search/groups [post]
func (h *SearchHandler) AdvancedGroupSearch(c *gin.Context) {
	var req dto.AdvancedGroupSearchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind advanced group search request")
		RespondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Advanced group search request validation failed")
		RespondWithValidationError(c, err)
		return
	}

	// Set default pagination if not provided
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.Limit <= 0 {
		req.Limit = 25
	}

	// Set default sorting if not provided
	if req.SortBy == "" {
		req.SortBy = "groupName"
	}
	if req.SortOrder == "" {
		req.SortOrder = "asc"
	}

	logger.Log.WithField("searchText", req.SearchText).
		WithField("authMethod", req.AuthMethod).
		WithField("role", req.Role).
		WithField("includeMemberCount", req.IncludeMemberCount).
		WithField("page", req.Page).
		WithField("limit", req.Limit).
		Debug("Processing advanced group search")

	// Perform search
	response, err := h.searchUsecase.AdvancedGroupSearch(c.Request.Context(), &req)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Advanced group search failed", err))
		}
		return
	}

	logger.Log.WithField("total", response.Total).
		WithField("returned", len(response.Groups)).
		WithField("searchDuration", response.Metadata.SearchDuration).
		Info("Advanced group search completed")

	RespondWithSuccess(c, nethttp.StatusOK, response)
}

// =================== SAVED SEARCHES ===================

// SaveSearch godoc
// @Summary Save search query
// @Description Save frequently used search criteria
// @Tags Advanced Search
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body dto.SavedSearchRequest true "Search to save"
// @Success 201 {object} dto.SavedSearchResponse
// @Failure 400 {object} dto.ErrorResponse
// @Router /api/openvpn/search/saved [post]
func (h *SearchHandler) SaveSearch(c *gin.Context) {
	var req dto.SavedSearchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind save search request")
		RespondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Save search request validation failed")
		RespondWithValidationError(c, err)
		return
	}

	// Get user from context
	username, exists := c.Get("username")
	if !exists {
		RespondWithError(c, errors.Unauthorized("User not authenticated", nil))
		return
	}

	logger.Log.WithField("name", req.Name).
		WithField("searchType", req.SearchType).
		WithField("username", username).
		Info("Saving search")

	// Save search
	response, err := h.searchUsecase.SaveSearch(c.Request.Context(), &req, username.(string))
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Failed to save search", err))
		}
		return
	}

	logger.Log.WithField("searchId", response.ID).
		WithField("name", response.Name).
		Info("Search saved successfully")

	RespondWithSuccess(c, nethttp.StatusCreated, response)
}

// GetSavedSearches godoc
// @Summary Get saved searches
// @Description Get list of saved searches for current user
// @Tags Advanced Search
// @Security BearerAuth
// @Produce json
// @Param searchType query string false "Filter by search type" Enums(users, groups)
// @Param includePublic query boolean false "Include public saved searches"
// @Success 200 {array} dto.SavedSearchResponse
// @Router /api/openvpn/search/saved [get]
func (h *SearchHandler) GetSavedSearches(c *gin.Context) {
	// Get user from context
	username, exists := c.Get("username")
	if !exists {
		RespondWithError(c, errors.Unauthorized("User not authenticated", nil))
		return
	}

	searchType := c.Query("searchType")
	includePublicStr := c.DefaultQuery("includePublic", "true")
	includePublic, _ := strconv.ParseBool(includePublicStr)

	logger.Log.WithField("username", username).
		WithField("searchType", searchType).
		WithField("includePublic", includePublic).
		Debug("Getting saved searches")

	// Get saved searches
	searches, err := h.searchUsecase.GetSavedSearches(c.Request.Context(), username.(string), searchType, includePublic)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Failed to get saved searches", err))
		}
		return
	}

	logger.Log.WithField("count", len(searches)).
		Info("Retrieved saved searches")

	RespondWithSuccess(c, nethttp.StatusOK, searches)
}

// ExecuteSavedSearch godoc
// @Summary Execute saved search
// @Description Execute a previously saved search
// @Tags Advanced Search
// @Security BearerAuth
// @Produce json
// @Param searchId path string true "Saved search ID"
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(50)
// @Success 200 {object} dto.AdvancedUserSearchResponse "User search results"
// @Success 200 {object} dto.AdvancedGroupSearchResponse "Group search results"
// @Failure 404 {object} dto.ErrorResponse
// @Router /api/openvpn/search/saved/{searchId}/execute [get]
func (h *SearchHandler) ExecuteSavedSearch(c *gin.Context) {
	searchId := c.Param("searchId")
	if searchId == "" {
		RespondWithError(c, errors.BadRequest("Search ID is required", nil))
		return
	}

	// Get user from context
	username, exists := c.Get("username")
	if !exists {
		RespondWithError(c, errors.Unauthorized("User not authenticated", nil))
		return
	}

	// Parse pagination
	pageStr := c.DefaultQuery("page", "1")
	page, _ := strconv.Atoi(pageStr)
	if page <= 0 {
		page = 1
	}

	limitStr := c.DefaultQuery("limit", "50")
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 {
		limit = 50
	}

	logger.Log.WithField("searchId", searchId).
		WithField("username", username).
		WithField("page", page).
		WithField("limit", limit).
		Info("Executing saved search")

	// Execute saved search
	result, err := h.searchUsecase.ExecuteSavedSearch(c.Request.Context(), searchId, username.(string), page, limit)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Failed to execute saved search", err))
		}
		return
	}

	logger.Log.WithField("searchId", searchId).
		Info("Saved search executed successfully")

	RespondWithSuccess(c, nethttp.StatusOK, result)
}

// DeleteSavedSearch godoc
// @Summary Delete saved search
// @Description Delete a saved search
// @Tags Advanced Search
// @Security BearerAuth
// @Param searchId path string true "Saved search ID"
// @Success 200 {object} dto.MessageResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /api/openvpn/search/saved/{searchId} [delete]
func (h *SearchHandler) DeleteSavedSearch(c *gin.Context) {
	searchId := c.Param("searchId")
	if searchId == "" {
		RespondWithError(c, errors.BadRequest("Search ID is required", nil))
		return
	}

	// Get user from context
	username, exists := c.Get("username")
	if !exists {
		RespondWithError(c, errors.Unauthorized("User not authenticated", nil))
		return
	}

	logger.Log.WithField("searchId", searchId).
		WithField("username", username).
		Info("Deleting saved search")

	// Delete saved search
	err := h.searchUsecase.DeleteSavedSearch(c.Request.Context(), searchId, username.(string))
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Failed to delete saved search", err))
		}
		return
	}

	logger.Log.WithField("searchId", searchId).
		Info("Saved search deleted successfully")

	RespondWithMessage(c, nethttp.StatusOK, "Saved search deleted successfully")
}

// =================== SEARCH SUGGESTIONS ===================

// GetSearchSuggestions godoc
// @Summary Get search suggestions
// @Description Get autocomplete suggestions for search fields
// @Tags Advanced Search
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body dto.SearchSuggestionsRequest true "Search suggestions criteria"
// @Success 200 {object} dto.SearchSuggestionsResponse
// @Failure 400 {object} dto.ErrorResponse
// @Router /api/openvpn/search/suggestions [post]
func (h *SearchHandler) GetSearchSuggestions(c *gin.Context) {
	var req dto.SearchSuggestionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind search suggestions request")
		RespondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Search suggestions request validation failed")
		RespondWithValidationError(c, err)
		return
	}

	// Set default limit if not provided
	if req.Limit <= 0 {
		req.Limit = 10
	}

	logger.Log.WithField("searchType", req.SearchType).
		WithField("query", req.Query).
		WithField("field", req.Field).
		WithField("limit", req.Limit).
		Debug("Getting search suggestions")

	// Get suggestions
	response, err := h.searchUsecase.GetSearchSuggestions(c.Request.Context(), &req)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Failed to get search suggestions", err))
		}
		return
	}

	logger.Log.WithField("suggestionsCount", len(response.Suggestions)).
		Debug("Search suggestions retrieved")

	RespondWithSuccess(c, nethttp.StatusOK, response)
}

// =================== QUICK SEARCH ===================

// QuickSearch godoc
// @Summary Quick search
// @Description Perform a quick text search across users and groups
// @Tags Advanced Search
// @Security BearerAuth
// @Produce json
// @Param q query string true "Search query"
// @Param type query string false "Search type" Enums(users, groups, all) default(all)
// @Param limit query int false "Result limit" default(20)
// @Success 200 {object} map[string]interface{} "Quick search results"
// @Router /api/openvpn/search/quick [get]
func (h *SearchHandler) QuickSearch(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		RespondWithError(c, errors.BadRequest("Search query is required", nil))
		return
	}

	searchType := c.DefaultQuery("type", "all")
	limitStr := c.DefaultQuery("limit", "20")
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	logger.Log.WithField("query", query).
		WithField("searchType", searchType).
		WithField("limit", limit).
		Debug("Performing quick search")

	// Perform quick search
	results, err := h.searchUsecase.QuickSearch(c.Request.Context(), query, searchType, limit)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Quick search failed", err))
		}
		return
	}

	logger.Log.WithField("query", query).
		WithField("resultsCount", len(results)).
		Info("Quick search completed")

	RespondWithSuccess(c, nethttp.StatusOK, results)
}

// =================== SEARCH ANALYTICS ===================

// GetSearchAnalytics godoc
// @Summary Get search analytics
// @Description Get analytics about search usage and patterns
// @Tags Advanced Search
// @Security BearerAuth
// @Produce json
// @Param period query string false "Analytics period" Enums(day, week, month) default(week)
// @Success 200 {object} map[string]interface{} "Search analytics data"
// @Router /api/openvpn/search/analytics [get]
func (h *SearchHandler) GetSearchAnalytics(c *gin.Context) {
	period := c.DefaultQuery("period", "week")

	// Get user from context for user-specific analytics
	username, exists := c.Get("username")
	if !exists {
		RespondWithError(c, errors.Unauthorized("User not authenticated", nil))
		return
	}

	logger.Log.WithField("period", period).
		WithField("username", username).
		Debug("Getting search analytics")

	// Get analytics
	analytics, err := h.searchUsecase.GetSearchAnalytics(c.Request.Context(), username.(string), period)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Failed to get search analytics", err))
		}
		return
	}

	logger.Log.WithField("period", period).
		Info("Search analytics retrieved")

	RespondWithSuccess(c, nethttp.StatusOK, analytics)
}

// =================== EXPORT SEARCH RESULTS ===================

// ExportSearchResults godoc
// @Summary Export search results
// @Description Export advanced search results to file
// @Tags Advanced Search
// @Security BearerAuth
// @Accept json
// @Produce application/octet-stream
// @Param format query string false "Export format" Enums(csv, xlsx, json) default(csv)
// @Param request body dto.AdvancedUserSearchRequest true "Search criteria for export"
// @Success 200 {file} file "Exported search results"
// @Router /api/openvpn/search/export [post]
func (h *SearchHandler) ExportSearchResults(c *gin.Context) {
	format := c.DefaultQuery("format", "csv")

	var req dto.AdvancedUserSearchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithError(err).Error("Failed to bind export search request")
		RespondWithError(c, errors.BadRequest("Invalid request format", err))
		return
	}

	// Validate request
	if err := validator.Validate(&req); err != nil {
		logger.Log.WithError(err).Error("Export search request validation failed")
		RespondWithValidationError(c, err)
		return
	}

	logger.Log.WithField("format", format).
		WithField("searchText", req.SearchText).
		Info("Exporting search results")

	// Export search results
	filename, content, err := h.searchUsecase.ExportSearchResults(c.Request.Context(), &req, format)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			RespondWithError(c, appErr)
		} else {
			RespondWithError(c, errors.InternalServerError("Failed to export search results", err))
		}
		return
	}

	logger.Log.WithField("filename", filename).
		WithField("format", format).
		Info("Search results exported successfully")

	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Type", h.getContentType(format))
	c.Data(nethttp.StatusOK, h.getContentType(format), content)
}

// =================== HELPER METHODS ===================

func (h *SearchHandler) getContentType(format string) string {
	switch format {
	case "csv":
		return "text/csv"
	case "xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case "json":
		return "application/json"
	default:
		return "text/csv"
	}
}
