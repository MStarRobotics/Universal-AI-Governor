package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/universal-ai-governor/internal/types"
)

// Config represents the complete application configuration for the Universal AI Governor.
// It encapsulates settings for server operation, governance components, security,
// logging, storage, and monitoring. This centralized configuration ensures consistency
// and simplifies management across the system.
type Config struct {
	Server     ServerConfig     `yaml:"server"`     // Server-related settings (HTTP, CORS, Rate Limiting)
	Governance GovernanceConfig `yaml:"governance"` // Core AI governance component configurations
	Security   SecurityConfig   `yaml:"security"`   // Security-specific settings (TLS, Auth)
	Logging    LoggingConfig    `yaml:"logging"`    // Logging behavior and destinations
	Storage    StorageConfig    `yaml:"storage"`    // Data storage configurations
	Monitoring MonitoringConfig `yaml:"monitoring"` // Metrics, health checks, and tracing
}

// ServerConfig contains settings for the Governor's HTTP server.
type ServerConfig struct {
	Mode         string        `yaml:"mode" default:"development"` // Application mode (e.g., "development", "production")
	ReadTimeout  int           `yaml:"read_timeout" default:"30"`  // Timeout for reading requests in seconds
	WriteTimeout int           `yaml:"write_timeout" default:"30"` // Timeout for writing responses in seconds
	IdleTimeout  int           `yaml:"idle_timeout" default:"120"` // Timeout for idle connections in seconds
	CORS         CORSConfig    `yaml:"cors"`         // Cross-Origin Resource Sharing settings
	RateLimit    RateLimitConfig `yaml:"rate_limit"` // API Rate Limiting settings
}

// CORSConfig contains settings for Cross-Origin Resource Sharing.
// It defines which origins, methods, and headers are allowed for cross-origin requests.
type CORSConfig struct {
	Enabled        bool     `yaml:"enabled" default:"true"`     // Enable or disable CORS
	AllowedOrigins []string `yaml:"allowed_origins"` // List of allowed origins (e.g., "https://example.com")
	AllowedMethods []string `yaml:"allowed_methods"` // List of allowed HTTP methods (e.g., "GET", "POST")
	AllowedHeaders []string `yaml:"allowed_headers"` // List of allowed HTTP headers
}

// RateLimitConfig contains settings for API rate limiting.
// This helps protect the server from abuse and ensures fair usage.
type RateLimitConfig struct {
	Enabled           bool          `yaml:"enabled" default:"true"` // Enable or disable rate limiting
	RequestsPerMinute int           `yaml:"requests_per_minute" default:"100"` // Maximum requests allowed per minute
	BurstSize         int           `yaml:"burst_size" default:"10"`          // Maximum burst of requests allowed
	CleanupInterval   time.Duration `yaml:"cleanup_interval" default:"5m"`    // Interval for cleaning up old rate limit data
}

// GovernanceConfig encapsulates the configurations for various AI governance components.
// This includes policy engines, moderation services, LLM adapters, guardrails, and audit settings.
type GovernanceConfig struct {
	PolicyEngine   PolicyEngineConfig   `yaml:"policy_engine"`   // Configuration for the policy evaluation engine
	Moderation     ModerationConfig     `yaml:"moderation"`     // Configuration for content moderation services
	LLMAdapters    []LLMAdapterConfig   `yaml:"llm_adapters"`    // Configurations for integrating with different LLMs
	Guardrails     GuardrailsConfig     `yaml:"guardrails"`     // Configuration for safety and compliance guardrails
	AuditSettings  AuditConfig          `yaml:"audit"`          // Configuration for audit logging behavior
}

// PolicyEngineConfig contains settings for the policy evaluation engine.
// This engine is responsible for enforcing governance rules defined in Rego.
type PolicyEngineConfig struct {
	Type        string            `yaml:"type" default:"opa"`      // Type of policy engine (e.g., "opa", "cel")
	PolicyDir   string            `yaml:"policy_dir" default:"./policies"` // Directory where Rego policy files are stored
	DataDir     string            `yaml:"data_dir" default:"./data"`     // Directory for external data used by policies
	BundleMode  bool              `yaml:"bundle_mode" default:"false"`   // Enable OPA bundle mode for policy distribution
	BundleURL   string            `yaml:"bundle_url"`            // URL to fetch policy bundles from
	Plugins     map[string]interface{} `yaml:"plugins"`           // Additional OPA plugins configuration
}

// ModerationConfig contains settings for the content moderation service.
// It defines which moderation providers are enabled and their behavior.
type ModerationConfig struct {
	Enabled   bool                    `yaml:"enabled" default:"true"`  // Enable or disable the moderation service
	Providers []ModerationProvider    `yaml:"providers"`   // List of individual moderation provider configurations
	Fallback  string                  `yaml:"fallback" default:"allow"` // Fallback behavior if moderation fails ("allow" or "block")
	Timeout   time.Duration           `yaml:"timeout" default:"10s"`     // Timeout for moderation requests
}

// ModerationProvider represents the configuration for a single moderation service provider.
type ModerationProvider struct {
	Name     string                 `yaml:"name"`     // Unique name for the provider instance
	Type     types.ModerationProviderType `yaml:"type"` // Type of moderation provider (e.g., "openai", "cohere")
	Enabled  bool                   `yaml:"enabled" default:"true"` // Enable or disable this specific provider
	Priority int                    `yaml:"priority" default:"1"`  // Priority for provider selection (lower is higher priority)
	Config   map[string]interface{} `yaml:"config"`   // Provider-specific configuration parameters
}

// LLMAdapterConfig contains settings for integrating with a specific Large Language Model.
type LLMAdapterConfig struct {
	Name     string                 `yaml:"name"`     // Unique name for the LLM adapter instance
	Type     string                 `yaml:"type"`     // Type of LLM (e.g., "openai", "anthropic", "local", "ollama")
	Enabled  bool                   `yaml:"enabled" default:"true"` // Enable or disable this specific LLM adapter
	Config   map[string]interface{} `yaml:"config"`   // LLM-specific configuration parameters (e.g., API keys, model names)
}

// GuardrailsConfig contains settings for the safety and compliance guardrails.
type GuardrailsConfig struct {
	Enabled          bool                   `yaml:"enabled" default:"true"`     // Enable or disable guardrails
	InputFilters     []GuardrailFilter      `yaml:"input_filters"`    // Filters applied to incoming data
	OutputFilters    []GuardrailFilter      `yaml:"output_filters"`   // Filters applied to outgoing data
	SchemaValidation bool                   `yaml:"schema_validation" default:"true"` // Enable schema validation for data
	CustomRules      map[string]interface{} `yaml:"custom_rules"`     // Custom rule definitions for guardrails
}

// GuardrailFilter represents a single filter within the guardrails system.
type GuardrailFilter struct {
	Name     string                 `yaml:"name"`     // Name of the filter
	Type     string                 `yaml:"type"`     // Type of filter (e.g., "regex", "pii_detector")
	Enabled  bool                   `yaml:"enabled" default:"true"` // Enable or disable this specific filter
	Config   map[string]interface{} `yaml:"config"`   // Filter-specific configuration
}

// AuditConfig contains settings for the audit logging subsystem.
type AuditConfig struct {
	Enabled       bool          `yaml:"enabled" default:"true"` // Enable or disable audit logging
	LogLevel      string        `yaml:"log_level" default:"info"` // Minimum log level for audit events
	RetentionDays int           `yaml:"retention_days" default:"90"` // Number of days to retain audit logs
	Destinations  []AuditDest   `yaml:"destinations"` // List of audit log destinations
	Sampling      SamplingConfig `yaml:"sampling"`     // Configuration for audit log sampling
}

// AuditDest represents a single destination for audit logs.
type AuditDest struct {
	Type   string                 `yaml:"type"`   // Type of destination (e.g., "file", "elasticsearch", "kafka")
	Config map[string]interface{} `yaml:"config"` // Destination-specific configuration
}

// SamplingConfig contains settings for sampling audit logs.
// This can be useful for high-volume environments to reduce storage costs.
type SamplingConfig struct {
	Enabled    bool    `yaml:"enabled" default:"false"` // Enable or disable sampling
	Rate       float64 `yaml:"rate" default:"0.1"`     // Sampling rate (e.g., 0.1 for 10%)
	MaxPerSecond int   `yaml:"max_per_second" default:"100"` // Maximum number of logs per second to sample
}

// SecurityConfig contains general security-related settings for the Governor.
type SecurityConfig struct {
	TLS  TLSConfig  `yaml:"tls"`  // Transport Layer Security settings
	Auth AuthConfig `yaml:"auth"` // Authentication and authorization settings
}

// TLSConfig contains settings for Transport Layer Security (TLS).
// This secures communication channels to and from the Governor.
type TLSConfig struct {
	Enabled    bool   `yaml:"enabled" default:"false"` // Enable or disable TLS
	CertFile   string `yaml:"cert_file"`   // Path to the TLS certificate file
	KeyFile    string `yaml:"key_file"`    // Path to the TLS private key file
	MinVersion string `yaml:"min_version" default:"1.2"` // Minimum TLS version to support
}

// AuthConfig contains settings for authentication and authorization.
type AuthConfig struct {
	Enabled   bool              `yaml:"enabled" default:"false"` // Enable or disable authentication
	Type      string            `yaml:"type" default:"jwt"`      // Type of authentication (e.g., "jwt", "oauth2", "apikey")
	Config    map[string]interface{} `yaml:"config"`   // Authentication provider-specific configuration
	RBAC      RBACConfig        `yaml:"rbac"`      // Role-Based Access Control settings
}

// RBACConfig contains settings for Role-Based Access Control.
// It defines roles and their associated permissions and resource access.
type RBACConfig struct {
	Enabled bool                   `yaml:"enabled" default:"false"` // Enable or disable RBAC
	Roles   map[string]RoleConfig  `yaml:"roles"`   // Map of role names to their configurations
}

// RoleConfig defines the permissions and resource access for a specific role.
type RoleConfig struct {
	Permissions []string `yaml:"permissions"` // List of permissions granted to this role
	Resources   []string `yaml:"resources"`   // List of resources this role can access
}

// LoggingConfig contains settings for the application's logging behavior.
type LoggingConfig struct {
	Level      string        `yaml:"level" default:"info"`     // Minimum log level to output (e.g., "debug", "info", "error")
	Format     string        `yaml:"format" default:"json"`    // Log output format (e.g., "json", "console")
	Output     []string      `yaml:"output" default:"[\"stdout\"]"` // List of log output destinations (e.g., "stdout", "file")
	File       FileLogConfig `yaml:"file"`         // File-specific logging settings
	Structured bool          `yaml:"structured" default:"true"` // Enable structured logging (e.g., JSON format)
}

// FileLogConfig contains settings for logging to a file.
type FileLogConfig struct {
	Path       string `yaml:"path" default:"./logs/governor.log"` // Path to the log file
	MaxSize    int    `yaml:"max_size" default:"100"`    // Maximum size of the log file before rotation (in MB)
	MaxBackups int    `yaml:"max_backups" default:"3"`     // Maximum number of old log files to retain
	MaxAge     int    `yaml:"max_age" default:"28"`      // Maximum number of days to retain old log files
	Compress   bool   `yaml:"compress" default:"true"`   // Compress old log files
}

// StorageConfig contains settings for data storage within the Governor.
type StorageConfig struct {
	Type   string                 `yaml:"type"`   // Type of storage backend (e.g., "file", "sqlite", "postgres", "redis")
	Config map[string]interface{} `yaml:"config"` // Storage backend-specific configuration
}

// MonitoringConfig contains settings for application monitoring and metrics.
type MonitoringConfig struct {
	Enabled    bool              `yaml:"enabled" default:"true"` // Enable or disable monitoring
	Prometheus PrometheusConfig  `yaml:"prometheus"` // Prometheus metrics configuration
	Health     HealthConfig      `yaml:"health"`     // Health check endpoint configuration
	Tracing    TracingConfig     `yaml:"tracing"`    // Distributed tracing configuration
}

// PrometheusConfig contains settings for Prometheus metrics exposure.
type PrometheusConfig struct {
	Enabled bool   `yaml:"enabled" default:"true"` // Enable or disable Prometheus metrics endpoint
	Path    string `yaml:"path" default:"/metrics"` // HTTP path for metrics endpoint
	Port    int    `yaml:"port" default:"9090"`     // Port for metrics endpoint
}

// HealthConfig contains settings for the health check endpoint.
type HealthConfig struct {
	Enabled  bool   `yaml:"enabled" default:"true"` // Enable or disable the health check endpoint
	Path     string `yaml:"path" default:"/health"` // HTTP path for health check endpoint
	Detailed bool   `yaml:"detailed" default:"true"` // Include detailed component health in the response
}

// TracingConfig contains settings for distributed tracing.
// This helps in observing request flows across different services.
type TracingConfig struct {
	Enabled   bool   `yaml:"enabled" default:"false"` // Enable or disable distributed tracing
	Provider  string `yaml:"provider" default:"jaeger"` // Tracing provider (e.g., "jaeger", "zipkin")
	Endpoint  string `yaml:"endpoint"`  // Tracing collector endpoint
	ServiceName string `yaml:"service_name" default:"universal-ai-governor"` // Service name for tracing data
}

// Load reads and parses the configuration file from the specified path.
// It applies default values, then overrides them with values from the file,
// and finally with environment variables. This provides a flexible configuration hierarchy.
func Load(path string) (*Config, error) {
	// Initialize a Config struct with all default values.
	config := &Config{
		Server: ServerConfig{
			Mode:         "development",
			ReadTimeout:  30,
			WriteTimeout: 30,
			IdleTimeout:  120,
			CORS: CORSConfig{
				Enabled:        true,
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
				AllowedHeaders: []string{"*"},
			},
			RateLimit: RateLimitConfig{
				Enabled:           true,
				RequestsPerMinute: 100,
				BurstSize:         10,
				CleanupInterval:   5 * time.Minute,
			},
		},
		Governance: GovernanceConfig{
			PolicyEngine: PolicyEngineConfig{
				Type:      "opa",
				PolicyDir: "./policies",
				DataDir:   "./data",
			},
			Moderation: ModerationConfig{
				Enabled:  true,
				Fallback: "allow",
				Timeout:  10 * time.Second,
			},
			Guardrails: GuardrailsConfig{
				Enabled:          true,
				SchemaValidation: true,
			},
			AuditSettings: AuditConfig{
				Enabled:       true,
				LogLevel:      "info",
				RetentionDays: 90,
			},
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			Output:     []string{"stdout"},
			Structured: true,
			File: FileLogConfig{
				Path:       "./logs/governor.log",
				MaxSize:    100,
				MaxBackups: 3,
				MaxAge:     28,
				Compress:   true,
			},
		},
		Storage: StorageConfig{
			Type: "file",
		},
		Monitoring: MonitoringConfig{
			Enabled: true,
			Prometheus: PrometheusConfig{
				Enabled: true,
				Path:    "/metrics",
				Port:    9090,
			},
			Health: HealthConfig{
				Enabled:  true,
				Path:     "/health",
				Detailed: true,
			},
		},
	}

	// Attempt to read the configuration from the specified file.
	// If the file doesn't exist, defaults will be used.
	if _, err := os.Stat(path); err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		// Unmarshal the YAML content into the Config struct.
		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	// Override configuration values with environment variables.
	// Environment variables provide a flexible way to adjust settings
	// without modifying configuration files.
	if err := loadFromEnv(config); err != nil {
		return nil, fmt.Errorf("failed to load environment variables: %w", err)
	}

	return config, nil
}

// loadFromEnv loads specific configuration parameters from environment variables.
// This function allows for external configuration of critical settings.
func loadFromEnv(config *Config) error {
	// Server configuration overrides.
	// Note: GOVERNOR_PORT is typically handled by the main application entry point
	// via command-line flags, so it's commented out here.
	// if port := os.Getenv("GOVERNOR_PORT"); port != "" {
	// 	// Port is handled in main.go via flag
	// }
	
	if mode := os.Getenv("GOVERNOR_MODE"); mode != "" {
		config.Server.Mode = mode
	}

	// Security configuration overrides.
	if tlsEnabled := os.Getenv("GOVERNOR_TLS_ENABLED"); tlsEnabled == "true" {
		config.Security.TLS.Enabled = true
	}
	
	if certFile := os.Getenv("GOVERNOR_TLS_CERT"); certFile != "" {
		config.Security.TLS.CertFile = certFile
	}
	
	if keyFile := os.Getenv("GOVERNOR_TLS_KEY"); keyFile != "" {
		config.Security.TLS.KeyFile = keyFile
	}

	// Logging configuration overrides.
	if logLevel := os.Getenv("GOVERNOR_LOG_LEVEL"); logLevel != "" {
		config.Logging.Level = logLevel
	}

	return nil
}

// Validate performs a sanity check on the loaded configuration.
// It ensures that critical settings are present and valid, preventing runtime errors.
func (c *Config) Validate() error {
	// Validate TLS settings: If TLS is enabled, certificate and key files must be specified.
	if c.Security.TLS.Enabled {
		if c.Security.TLS.CertFile == "" || c.Security.TLS.KeyFile == "" {
			return fmt.Errorf("TLS enabled but cert_file or key_file not specified")
		}
	}

	// Validate policy engine configuration: Ensure a policy engine type is defined.
	if c.Governance.PolicyEngine.Type == "" {
		return fmt.Errorf("policy engine type must be specified")
	}

	// Validate logging level: Ensure the configured log level is one of the recognized values.
	validLogLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true, "fatal": true,
	}
	if !validLogLevels[c.Logging.Level] {
		return fmt.Errorf("invalid log level: %s", c.Logging.Level)
	}

	return nil
}