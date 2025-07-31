package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	// Create Gin router
	r := gin.Default()

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "universal-ai-governor",
			"version": "1.0.0",
		})
	})

	// API routes
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

		api.GET("/audit", func(c *gin.Context) {
			c.JSON(http.StatusOK, []map[string]interface{}{
				{
					"id":        "1",
					"user_id":   "1",
					"action":    "login",
					"resource":  "system",
					"timestamp": time.Now().Format(time.RFC3339),
				},
			})
		})
	}

	// Create HTTP server
	srv := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	// Start server in a goroutine
	go func() {
		log.Println("Starting Universal AI Governor on :8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exited")
}
