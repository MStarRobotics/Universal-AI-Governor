package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/universal-ai-governor/internal/api"
	"github.com/universal-ai-governor/internal/config"
	"github.com/universal-ai-governor/internal/governance"
	"github.com/universal-ai-governor/internal/logging"
	"github.com/universal-ai-governor/internal/middleware"
)

var (
	configPath = flag.String("config", "config.yaml", "Path to configuration file")
	port       = flag.String("port", "8080", "Server port")
	version    = "1.0.0"
	buildTime  = "unknown"
	gitCommit  = "unknown"
)

func main() {
	flag.Parse()

	// Print version info
	fmt.Printf("Universal AI Governor v%s (built: %s, commit: %s)\n", version, buildTime, gitCommit)

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logging
	logger, err := logging.NewLogger(cfg.Logging)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	// Initialize governance engine
	govEngine, err := governance.NewEngine(cfg.Governance, logger)
	if err != nil {
		logger.Fatal("Failed to initialize governance engine", "error", err)
	}

	// Setup HTTP server
	if cfg.Server.Mode == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	
	// Add middleware
	router.Use(middleware.Logger(logger))
	router.Use(middleware.Recovery(logger))
	router.Use(middleware.CORS(cfg.Server.CORS))
	router.Use(middleware.RateLimit(cfg.Server.RateLimit))
	
	if cfg.Security.TLS.Enabled {
		router.Use(middleware.TLS(cfg.Security.TLS))
	}
	
	if cfg.Security.Auth.Enabled {
		router.Use(middleware.Auth(cfg.Security.Auth))
	}

	// Setup API routes
	apiHandler := api.NewHandler(govEngine, logger)
	api.SetupRoutes(router, apiHandler)

	// Create HTTP server
	server := &http.Server{
		Addr:         ":" + *port,
		Handler:      router,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(cfg.Server.IdleTimeout) * time.Second,
	}

	// Start server in goroutine
	go func() {
		logger.Info("Starting Universal AI Governor server", 
			"port", *port, 
			"version", version,
			"tls_enabled", cfg.Security.TLS.Enabled)
		
		var err error
		if cfg.Security.TLS.Enabled {
			err = server.ListenAndServeTLS(cfg.Security.TLS.CertFile, cfg.Security.TLS.KeyFile)
		} else {
			err = server.ListenAndServe()
		}
		
		if err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server", "error", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown", "error", err)
	}

	// Cleanup governance engine
	if err := govEngine.Close(); err != nil {
		logger.Error("Error closing governance engine", "error", err)
	}

	logger.Info("Server exited")
}
