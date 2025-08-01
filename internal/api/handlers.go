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

// Handler encapsulates the API endpoints and their underlying governance engine interactions.
// It acts as the bridge between incoming HTTP requests and the core logic of the Governor.
type Handler struct {
	engine *governance.Engine // The core governance engine instance
	logger logging.Logger     // Logger for API-specific events and errors
}

// NewHandler creates and returns a new Handler instance.
// This function is the entry point for setting up the API layer.
func NewHandler(engine *governance.Engine, logger logging.Logger) *Handler {
	return &Handler{
		engine: engine,
		logger: logger,
	}
}

// ProcessGovernanceRequest handles incoming requests for AI governance evaluation.
// It binds the request body to a GovernanceRequest, validates it, and then dispatches
// it to the governance engine for processing. The response from the engine is then
// translated into an appropriate HTTP response.
func (h *Handler) ProcessGovernanceRequest(c *gin.Context) {
	var req types.GovernanceRequest
	// Attempt to bind the JSON request body to the GovernanceRequest struct.
	if err := c.ShouldBindJSON(&req); err != nil {
		// If binding fails, it indicates a malformed request body.
		h.logger.Error("Invalid request body", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	// Perform basic validation of essential fields in the GovernanceRequest.
	// This ensures that the request contains the minimum required information.
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

	// Dispatch the validated request to the core governance engine for processing.
	response, err := h.engine.ProcessRequest(c.Request.Context(), &req)
	if err != nil {
		// If the governance engine encounters an error, log it and return an internal server error.
		h.logger.Error("Failed to process governance request", "error", err, "request_id", req.RequestID)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":      "Failed to process request",
			"request_id": req.RequestID,
		})
		return
	}

	// Determine the appropriate HTTP status code based on the governance engine's response status.
	var httpStatus int
	switch response.Status {
	case types.StatusAllowed:
		httpStatus = http.StatusOK // Request was allowed by all policies and checks.
	case types.StatusBlocked:
		httpStatus = http.StatusForbidden // Request was blocked by a governance rule.
	case types.StatusError:
		httpStatus = http.StatusInternalServerError // An internal error occurred during processing.
	default:
		httpStatus = http.StatusInternalServerError // Catch-all for unexpected statuses.
	}

	// Return the governance response as JSON with the determined HTTP status.
	c.JSON(httpStatus, response)
}

// GetHealth returns the current health status of the entire system.
// It can provide a simplified overview or a detailed breakdown of component health.
func (h *Handler) GetHealth(c *gin.Context) {
	// Check if a detailed health report is requested via query parameter.
	detailed := c.Query("detailed") == "true"
	
	// Retrieve the overall health status from the governance engine.
	health := h.engine.Health()
	
	// If only a simplified report is requested, return a subset of the health data.
	if !detailed {
		c.JSON(http.StatusOK, gin.H{
			"status":    health.Status,
			"timestamp": health.Timestamp,
		})
		return
	}

	// Determine the HTTP status code based on the overall health status.
	var httpStatus int
	switch health.Status {
	case types.HealthStatusHealthy:
		httpStatus = http.StatusOK
	case types.HealthStatusDegraded:
		httpStatus = http.StatusPartialContent // Some components are not fully healthy.
	case types.HealthStatusUnhealthy:
		httpStatus = http.StatusServiceUnavailable // Critical components are unhealthy.
	default:
		httpStatus = http.StatusInternalServerError
	}

	// Return the full detailed health status as JSON.
	c.JSON(httpStatus, health)
}

// GetMetrics returns a snapshot of the system's operational metrics.
// This endpoint provides insights into performance, request volumes, and error rates.
func (h *Handler) GetMetrics(c *gin.Context) {
	// Retrieve the metrics instance from the governance engine.
	metrics := h.engine.GetMetrics()
	// Get a snapshot of the current metrics data.
	snapshot := metrics.GetSnapshot()
	
	// Return the metrics snapshot as JSON.
	c.JSON(http.StatusOK, snapshot)
}

// GetLLMAdapters returns a list of all configured and available LLM adapters.
// This allows clients to discover which LLM integrations are active.
func (h *Handler) GetLLMAdapters(c *gin.Context) {
	// Retrieve the list of LLM adapter names from the governance engine.
	adapters := h.engine.GetLLMAdapters()
	
	// Return the list of adapters and their count as JSON.
	c.JSON(http.StatusOK, gin.H{
		"adapters": adapters,
		"count":    len(adapters),
	})
}

// ValidateInput provides a way to validate input content without triggering
// a full LLM processing pipeline. This is useful for pre-screening or testing
// guardrail rules in isolation.
func (h *Handler) ValidateInput(c *gin.Context) {
	// Define an anonymous struct to bind the incoming JSON request.
	var req struct {
		Prompt  string                 `json:"prompt" binding:"required"`
		UserID  string                 `json:"user_id" binding:"required"`
		Context map[string]interface{} `json:"context,omitempty"`
	}

	// Bind and validate the request body.
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	// Construct a GovernanceRequest specifically for input validation.
	// Note: LLMAdapter and LLMOptions are intentionally omitted to bypass LLM processing.
	govReq := &types.GovernanceRequest{
		Prompt:  req.Prompt,
		UserID:  req.UserID,
		Context: req.Context,
	}

	// Process the request through the governance engine. The engine will apply
	// input moderation and guardrails, but skip LLM interaction.
	response, err := h.engine.ProcessRequest(c.Request.Context(), govReq)
	if err != nil {
		// Log and return an error if validation fails.
		h.logger.Error("Failed to validate input", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to validate input",
		})
		return
	}

	// Return the validation result, indicating whether the input is considered valid
	// by the governance rules.
	c.JSON(http.StatusOK, gin.H{
		"valid":      response.Status == types.StatusAllowed, // True if the input was allowed
		"status":     response.Status,
		"reason":     response.Reason,
		"request_id": response.RequestID,
		"metadata":   response.Metadata,
	})
}

// GetVersion returns detailed version information about the Governor instance.
// This includes build time, git commit, and Go version, useful for debugging and auditing.
func (h *Handler) GetVersion(c *gin.Context) {
	// TODO: Populate these fields dynamically from build information.
	c.JSON(http.StatusOK, gin.H{
		"version":    "1.0.0",
		"build_time": "2024-01-01T00:00:00Z",
		"git_commit": "abc123",
		"go_version": "1.21.0",
	})
}

// GetStatus returns a high-level operational status of the Governor.
// This is a quick check to see if the service is running.
func (h *Handler) GetStatus(c *gin.Context) {
	// TODO: Implement actual uptime calculation from the service start time.
	c.JSON(http.StatusOK, gin.H{
		"status":    "running",
		"timestamp": time.Now(),
		"uptime":    time.Since(time.Now()).String(), // Placeholder: should be actual uptime.
	})
}

// BatchProcessRequests handles multiple governance requests in a single API call.
// This can improve efficiency by reducing overhead for multiple small requests.
func (h *Handler) BatchProcessRequests(c *gin.Context) {
	// Define an anonymous struct to bind the batch request body.
	var batchReq struct {
		Requests []types.GovernanceRequest `json:"requests" binding:"required"`
	}

	// Bind and validate the batch request.
	if err := c.ShouldBindJSON(&batchReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body for batch processing",
			"details": err.Error(),
		})
		return
	}

	// Validate the size of the batch to prevent excessive resource consumption.
	maxBatchSize := 10 // This should ideally be configurable.
	if len(batchReq.Requests) > maxBatchSize {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":          "Batch size exceeds maximum allowed",
			"max_batch_size": maxBatchSize,
		})
		return
	}

	// Prepare a slice to store responses for each request in the batch.
	responses := make([]*types.GovernanceResponse, len(batchReq.Requests))
	
	// Iterate through each request in the batch and process it individually.
	for i, req := range batchReq.Requests {
		// Perform basic validation for each individual request within the batch.
		if req.Prompt == "" || req.UserID == "" {
			responses[i] = &types.GovernanceResponse{
				RequestID: req.RequestID,
				Status:    types.StatusError,
				Error:     "Prompt and UserID are required for each batch request",
			}
			continue // Move to the next request in the batch.
		}

		// Process the individual request using the governance engine.
		response, err := h.engine.ProcessRequest(c.Request.Context(), &req)
		if err != nil {
			// Log errors for individual batch requests.
			h.logger.Error("Failed to process batch request", "error", err, "index", i, "request_id", req.RequestID)
			responses[i] = &types.GovernanceResponse{
				RequestID: req.RequestID,
				Status:    types.StatusError,
				Error:     "Failed to process request in batch",
			}
		} else {
			responses[i] = response
		}
	}

	// Return the aggregated responses for the entire batch.
	c.JSON(http.StatusOK, gin.H{
		"responses": responses,
		"count":     len(responses),
	})
}

// GetAuditLogs retrieves audit logs from the system, supporting pagination and filtering.
// This endpoint is crucial for compliance and forensic analysis.
func (h *Handler) GetAuditLogs(c *gin.Context) {
	// Parse pagination and filtering parameters from the query string.
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	userID := c.Query("user_id")
	status := c.Query("status")
	
	// Validate and sanitize pagination parameters.
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 1000 {
		limit = 50
	}

	// TODO: Implement actual audit log retrieval logic.
	// This would involve calling a method on `h.engine.auditSvc` to query the audit store.
	// For now, we return a placeholder response.
	c.JSON(http.StatusOK, gin.H{
		"logs":       []interface{}{}, // Placeholder: would contain actual audit logs.
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

// UpdateConfiguration allows for dynamic, runtime updates to the Governor's configuration.
// This enables adjusting settings without requiring a service restart.
func (h *Handler) UpdateConfiguration(c *gin.Context) {
	// Bind the incoming JSON request body to a generic map.
	var configUpdate map[string]interface{}
	if err := c.ShouldBindJSON(&configUpdate); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid configuration update payload",
			"details": err.Error(),
		})
		return
	}

	// TODO: Implement actual configuration update logic.
	// This would involve validating the update, applying it to the running configuration,
	// and potentially re-initializing affected components.
	h.logger.Info("Configuration update requested", "update", configUpdate)
	
	// Return a success message, indicating that the update request was received.
	c.JSON(http.StatusOK, gin.H{
		"message": "Configuration update received",
		"status":  "pending", // Placeholder: would be "applied" after actual update.
	})
}

// GetPolicies returns the list of all active governance policies.
// This endpoint provides visibility into the rules currently enforced by the system.
func (h *Handler) GetPolicies(c *gin.Context) {
	// TODO: Implement actual policy retrieval from the policy engine.
	// This would involve calling a method on `h.engine.policyEngine`.
	// For now, we return a placeholder response.
	c.JSON(http.StatusOK, gin.H{
		"policies": []interface{}{}, // Placeholder: would contain actual policy objects.
		"count":    0,
	})
}

// CreatePolicy handles the creation of a new governance policy.
// Policies are typically defined in Rego and are used by the policy engine.
func (h *Handler) CreatePolicy(c *gin.Context) {
	// Bind the incoming JSON request body to a PolicyDocument struct.
	var policy types.PolicyDocument
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid policy document format",
			"details": err.Error(),
		})
		return
	}

	// Validate essential fields of the new policy.
	if policy.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Policy name is required",
		})
		return
	}

	// TODO: Implement actual policy creation logic.
	// This would involve storing the policy in the policy engine's store and reloading policies.
	h.logger.Info("Policy creation requested", "policy_name", policy.Name)
	
	// Return a success message with the ID of the newly created policy.
	c.JSON(http.StatusCreated, gin.H{
		"message":   "Policy created successfully",
		"policy_id": policy.ID, // Assuming the policy engine assigns an ID.
	})
}

// UpdatePolicy handles updates to existing governance policies.
// It identifies the policy by ID and applies the changes from the request body.
func (h *Handler) UpdatePolicy(c *gin.Context) {
	// Extract the policy ID from the URL parameters.
	policyID := c.Param("id")
	if policyID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Policy ID is required in the URL path",
		})
		return
	}

	// Bind the incoming JSON request body to a PolicyDocument struct.
	var policy types.PolicyDocument
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid policy document format for update",
			"details": err.Error(),
		})
		return
	}

	// TODO: Implement actual policy update logic.
	// This would involve finding the policy by ID, updating its content, and reloading policies.
	h.logger.Info("Policy update requested", "policy_id", policyID)
	
	// Return a success message for the update operation.
	c.JSON(http.StatusOK, gin.H{
		"message":   "Policy updated successfully",
		"policy_id": policyID,
	})
}

// DeletePolicy handles the deletion of an existing governance policy.
// It identifies the policy by ID from the URL parameters.
func (h *Handler) DeletePolicy(c *gin.Context) {
	// Extract the policy ID from the URL parameters.
	policyID := c.Param("id")
	if policyID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Policy ID is required in the URL path",
		})
		return
	}

	// TODO: Implement actual policy deletion logic.
	// This would involve removing the policy from the policy engine's store and reloading policies.
	h.logger.Info("Policy deletion requested", "policy_id", policyID)
	
	// Return a success message for the deletion operation.
	c.JSON(http.StatusOK, gin.H{
		"message":   "Policy deleted successfully",
		"policy_id": policyID,
	})
}
