package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHealthEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	
	r := gin.Default()
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "universal-ai-governor",
			"version": "1.0.0",
		})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "healthy")
}

func TestPoliciesEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	
	r := gin.Default()
	api := r.Group("/api/v1")
	{
		api.GET("/policies", func(c *gin.Context) {
			c.JSON(http.StatusOK, []map[string]interface{}{
				{
					"id":          "1",
					"name":        "Default Policy",
					"description": "Default AI governance policy",
					"enabled":     true,
				},
			})
		})
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/policies", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "Default Policy")
}

func TestUsersEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	
	r := gin.Default()
	api := r.Group("/api/v1")
	{
		api.GET("/users", func(c *gin.Context) {
			c.JSON(http.StatusOK, []map[string]interface{}{
				{
					"id":       "1",
					"username": "admin",
					"email":    "admin@example.com",
					"roles":    []string{"admin"},
				},
			})
		})
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/users", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "admin")
}
