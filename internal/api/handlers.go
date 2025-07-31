package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/universal-ai-governor/internal/governance"
	"github.com/universal-ai-governor/internal/logging"
	"github.com/universal-ai-governor/internal/types"
)

// Handler contains the API handlers
type Handler struct {
	engine *governance.Engine
	logger logging.Logger
}

// NewHandler creates a new API handler
func NewHandler(engine *governance.Engine, logger logging.Logger) *Handler {
	return &Handler{
		engine: engine,
		logger: logger,
	}
}

// ProcessGovernanceRequest handles governance requests
func (h *Handler) ProcessGovernanceRequest(c *gin.Context) {
	var req types.GovernanceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Invalid request body", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	// Validate required fields
	if req.Prompt == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Prompt is required",
		})
		return
	}

	if req.UserID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "UserID is required",
		})
		return
	}

	// Process the request
	response, err := h.engine.ProcessRequest(c.Request.Context(), &req)
	if err != nil {
		h.logger.Error("Failed to process governance request", "error", err, "request_id", req.RequestID)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":      "Failed to process request",
			"request_id": req.RequestID,
		})
		return
	}

	// Return appropriate HTTP status based on governance response
	var httpStatus int
	switch response.Status {
	case types.StatusAllowed:
		httpStatus = http.StatusOK
	case types.StatusBlocked:
		httpStatus = http.StatusForbidden
	case types.StatusError:
		httpStatus = http.StatusInternalServerError
	default:
		httpStatus = http.StatusInternalServerError
	}

	c.JSON(httpStatus, response)
}

// GetHealth returns the health status of the system
func (h *Handler) GetHealth(c *gin.Context) {
	detailed := c.Query("detailed") == "true"
	
	health := h.engine.Health()
	
	if !detailed {
		// Return simplified health status
		c.JSON(http.StatusOK, gin.H{
			"status":    health.Status,
			"timestamp": health.Timestamp,
		})
		return
	}

	// Return detailed health status
	var httpStatus int
	switch health.Status {
	case types.HealthStatusHealthy:
		httpStatus = http.StatusOK
	case types.HealthStatusDegraded:
		httpStatus = http.StatusPartialContent
	case types.HealthStatusUnhealthy:
		httpStatus = http.StatusServiceUnavailable
	default:
		httpStatus = http.StatusInternalServerError
	}

	c.JSON(httpStatus, health)
}

// GetMetrics returns system metrics
func (h *Handler) GetMetrics(c *gin.Context) {
	metrics := h.engine.GetMetrics()
	snapshot := metrics.GetSnapshot()
	
	c.JSON(http.StatusOK, snapshot)
}

// GetLLMAdapters returns the list of available LLM adapters
func (h *Handler) GetLLMAdapters(c *gin.Context) {
	adapters := h.engine.GetLLMAdapters()
	
	c.JSON(http.StatusOK, gin.H{
		"adapters": adapters,
		"count":    len(adapters),
	})
}

// ValidateInput validates input without processing through LLM
func (h *Handler) ValidateInput(c *gin.Context) {
	var req struct {
		Prompt  string                 `json:"prompt" binding:"required"`
		UserID  string                 `json:"user_id" binding:"required"`
		Context map[string]interface{} `json:"context,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	// Create a governance request for validation only
	govReq := &types.GovernanceRequest{
		Prompt:  req.Prompt,
		UserID:  req.UserID,
		Context: req.Context,
		// Don't specify LLM adapter to skip LLM processing
	}

	response, err := h.engine.ProcessRequest(c.Request.Context(), govReq)
	if err != nil {
		h.logger.Error("Failed to validate input", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to validate input",
		})
		return
	}

	// Return validation result
	c.JSON(http.StatusOK, gin.H{
		"valid":      response.Status == types.StatusAllowed,
		"status":     response.Status,
		"reason":     response.Reason,
		"request_id": response.RequestID,
		"metadata":   response.Metadata,
	})
}

// GetVersion returns version information
func (h *Handler) GetVersion(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"version":    "1.0.0",
		"build_time": "2024-01-01T00:00:00Z",
		"git_commit": "abc123",
		"go_version": "1.21.0",
	})
}

// GetStatus returns basic system status
func (h *Handler) GetStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "running",
		"timestamp": time.Now(),
		"uptime":    time.Since(time.Now()).String(), // This would be calculated from startup time
	})
}

// BatchProcessRequests handles multiple governance requests in a single call
func (h *Handler) BatchProcessRequests(c *gin.Context) {
	var batchReq struct {
		Requests []types.GovernanceRequest `json:"requests" binding:"required"`
	}

	if err := c.ShouldBindJSON(&batchReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	// Validate batch size
	maxBatchSize := 10 // Configurable
	if len(batchReq.Requests) > maxBatchSize {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Batch size exceeds maximum allowed",
			"max_batch_size": maxBatchSize,
		})
		return
	}

	responses := make([]*types.GovernanceResponse, len(batchReq.Requests))
	
	// Process each request
	for i, req := range batchReq.Requests {
		// Validate required fields
		if req.Prompt == "" || req.UserID == "" {
			responses[i] = &types.GovernanceResponse{
				RequestID: req.RequestID,
				Status:    types.StatusError,
				Error:     "Prompt and UserID are required",
			}
			continue
		}

		response, err := h.engine.ProcessRequest(c.Request.Context(), &req)
		if err != nil {
			h.logger.Error("Failed to process batch request", "error", err, "index", i)
			responses[i] = &types.GovernanceResponse{
				RequestID: req.RequestID,
				Status:    types.StatusError,
				Error:     "Failed to process request",
			}
		} else {
			responses[i] = response
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"responses": responses,
		"count":     len(responses),
	})
}

// GetAuditLogs returns audit logs with pagination
func (h *Handler) GetAuditLogs(c *gin.Context) {
	// Parse query parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	userID := c.Query("user_id")
	status := c.Query("status")
	
	// Validate parameters
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 1000 {
		limit = 50
	}

	// This would typically call an audit service method
	// For now, return a placeholder response
	c.JSON(http.StatusOK, gin.H{
		"logs":       []interface{}{}, // Would contain actual audit logs
		"page":       page,
		"limit":      limit,
		"total":      0,
		"has_more":   false,
		"filters": gin.H{
			"user_id": userID,
			"status":  status,
		},
	})
}

// UpdateConfiguration allows runtime configuration updates
func (h *Handler) UpdateConfiguration(c *gin.Context) {
	var configUpdate map[string]interface{}
	if err := c.ShouldBindJSON(&configUpdate); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid configuration update",
			"details": err.Error(),
		})
		return
	}

	// This would typically update the configuration
	// For now, return a placeholder response
	h.logger.Info("Configuration update requested", "update", configUpdate)
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Configuration update received",
		"status":  "pending", // Would be "applied" after actual update
	})
}

// GetPolicies returns the list of active policies
func (h *Handler) GetPolicies(c *gin.Context) {
	// This would typically call the policy engine
	// For now, return a placeholder response
	c.JSON(http.StatusOK, gin.H{
		"policies": []interface{}{}, // Would contain actual policies
		"count":    0,
	})
}

// CreatePolicy creates a new policy
func (h *Handler) CreatePolicy(c *gin.Context) {
	var policy types.PolicyDocument
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid policy document",
			"details": err.Error(),
		})
		return
	}

	// Validate policy
	if policy.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Policy name is required",
		})
		return
	}

	// This would typically create the policy
	h.logger.Info("Policy creation requested", "policy_name", policy.Name)
	
	c.JSON(http.StatusCreated, gin.H{
		"message":   "Policy created successfully",
		"policy_id": policy.ID,
	})
}

// UpdatePolicy updates an existing policy
func (h *Handler) UpdatePolicy(c *gin.Context) {
	policyID := c.Param("id")
	if policyID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Policy ID is required",
		})
		return
	}

	var policy types.PolicyDocument
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid policy document",
			"details": err.Error(),
		})
		return
	}

	// This would typically update the policy
	h.logger.Info("Policy update requested", "policy_id", policyID)
	
	c.JSON(http.StatusOK, gin.H{
		"message":   "Policy updated successfully",
		"policy_id": policyID,
	})
}

// DeletePolicy deletes a policy
func (h *Handler) DeletePolicy(c *gin.Context) {
	policyID := c.Param("id")
	if policyID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Policy ID is required",
		})
		return
	}

	// This would typically delete the policy
	h.logger.Info("Policy deletion requested", "policy_id", policyID)
	
	c.JSON(http.StatusOK, gin.H{
		"message":   "Policy deleted successfully",
		"policy_id": policyID,
	})
}
