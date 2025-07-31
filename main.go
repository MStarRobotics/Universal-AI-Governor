package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/cors"
)

// Policy represents an AI governance policy
type Policy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Enabled     bool                   `json:"enabled"`
	Rules       map[string]interface{} `json:"rules"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// User represents a system user
type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Roles     []string  `json:"roles"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID        string                 `json:"id"`
	UserID    string                 `json:"user_id"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Details   map[string]interface{} `json:"details"`
	Timestamp time.Time              `json:"timestamp"`
	IPAddress string                 `json:"ip_address,omitempty"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string    `json:"status"`
	Service   string    `json:"service"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
}

func main() {
	// Set Gin to release mode in production
	gin.SetMode(gin.ReleaseMode)

	// Create Gin router
	r := gin.Default()

	// Add CORS middleware
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"*"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Health check endpoint
	r.GET("/health", healthCheck)

	// API v1 routes
	v1 := r.Group("/api/v1")
	{
		v1.GET("/policies", getPolicies)
		v1.GET("/users", getUsers)
		v1.GET("/audit", getAuditLogs)
	}

	// Start server
	log.Println("Starting Universal AI Governor server on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// healthCheck returns the health status of the service
func healthCheck(c *gin.Context) {
	response := HealthResponse{
		Status:    "healthy",
		Service:   "universal-ai-governor",
		Version:   "1.0.0",
		Timestamp: time.Now(),
	}
	c.JSON(http.StatusOK, response)
}

// getPolicies returns all policies
func getPolicies(c *gin.Context) {
	now := time.Now()
	policies := []Policy{
		{
			ID:          "1",
			Name:        "Default Policy",
			Description: "Default AI governance policy",
			Enabled:     true,
			Rules:       map[string]interface{}{},
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          "2",
			Name:        "Strict Policy",
			Description: "Strict AI governance policy with enhanced security",
			Enabled:     true,
			Rules: map[string]interface{}{
				"max_tokens":       1000,
				"require_approval": true,
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
	}
	c.JSON(http.StatusOK, policies)
}

// getUsers returns all users
func getUsers(c *gin.Context) {
	now := time.Now()
	users := []User{
		{
			ID:        "1",
			Username:  "admin",
			Email:     "admin@example.com",
			Roles:     []string{"admin", "user"},
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:        "2",
			Username:  "analyst",
			Email:     "analyst@example.com",
			Roles:     []string{"analyst", "user"},
			CreatedAt: now,
			UpdatedAt: now,
		},
	}
	c.JSON(http.StatusOK, users)
}

// getAuditLogs returns audit logs
func getAuditLogs(c *gin.Context) {
	now := time.Now()
	logs := []AuditLog{
		{
			ID:       "1",
			UserID:   "admin",
			Action:   "login",
			Resource: "system",
			Details: map[string]interface{}{
				"ip_address": "127.0.0.1",
				"user_agent": "Mozilla/5.0",
			},
			Timestamp: now,
			IPAddress: "127.0.0.1",
		},
		{
			ID:        "2",
			UserID:    "analyst",
			Action:    "policy_view",
			Resource:  "policy:1",
			Details:   map[string]interface{}{},
			Timestamp: now,
		},
	}
	c.JSON(http.StatusOK, logs)
}
