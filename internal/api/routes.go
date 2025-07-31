package api

import (
	"github.com/gin-gonic/gin"
)

// SetupRoutes configures all API routes
func SetupRoutes(router *gin.Engine, handler *Handler) {
	// API version prefix
	v1 := router.Group("/api/v1")
	
	// Core governance endpoints
	governance := v1.Group("/governance")
	{
		governance.POST("/process", handler.ProcessGovernanceRequest)
		governance.POST("/validate", handler.ValidateInput)
		governance.POST("/batch", handler.BatchProcessRequests)
	}

	// LLM adapter endpoints
	llm := v1.Group("/llm")
	{
		llm.GET("/adapters", handler.GetLLMAdapters)
	}

	// Policy management endpoints
	policies := v1.Group("/policies")
	{
		policies.GET("", handler.GetPolicies)
		policies.POST("", handler.CreatePolicy)
		policies.PUT("/:id", handler.UpdatePolicy)
		policies.DELETE("/:id", handler.DeletePolicy)
	}

	// Audit and logging endpoints
	audit := v1.Group("/audit")
	{
		audit.GET("/logs", handler.GetAuditLogs)
	}

	// System management endpoints
	system := v1.Group("/system")
	{
		system.GET("/health", handler.GetHealth)
		system.GET("/metrics", handler.GetMetrics)
		system.GET("/status", handler.GetStatus)
		system.GET("/version", handler.GetVersion)
		system.PUT("/config", handler.UpdateConfiguration)
	}

	// Health check endpoint (also available at root level)
	router.GET("/health", handler.GetHealth)
	router.GET("/ready", handler.GetHealth)
	
	// Metrics endpoint for Prometheus
	router.GET("/metrics", handler.GetMetrics)

	// Root endpoint
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"service": "Universal AI Governor",
			"version": "1.0.0",
			"status":  "running",
			"endpoints": gin.H{
				"governance": "/api/v1/governance",
				"policies":   "/api/v1/policies",
				"audit":      "/api/v1/audit",
				"system":     "/api/v1/system",
				"health":     "/health",
				"metrics":    "/metrics",
			},
		})
	})
}
