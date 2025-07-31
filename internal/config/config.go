package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete application configuration
type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Governance GovernanceConfig `yaml:"governance"`
	Security   SecurityConfig   `yaml:"security"`
	Logging    LoggingConfig    `yaml:"logging"`
	Storage    StorageConfig    `yaml:"storage"`
	Monitoring MonitoringConfig `yaml:"monitoring"`
}

// ServerConfig contains HTTP server configuration
type ServerConfig struct {
	Mode         string        `yaml:"mode" default:"development"`
	ReadTimeout  int           `yaml:"read_timeout" default:"30"`
	WriteTimeout int           `yaml:"write_timeout" default:"30"`
	IdleTimeout  int           `yaml:"idle_timeout" default:"120"`
	CORS         CORSConfig    `yaml:"cors"`
	RateLimit    RateLimitConfig `yaml:"rate_limit"`
}

// CORSConfig contains CORS configuration
type CORSConfig struct {
	Enabled        bool     `yaml:"enabled" default:"true"`
	AllowedOrigins []string `yaml:"allowed_origins"`
	AllowedMethods []string `yaml:"allowed_methods"`
	AllowedHeaders []string `yaml:"allowed_headers"`
}

// RateLimitConfig contains rate limiting configuration
type RateLimitConfig struct {
	Enabled     bool          `yaml:"enabled" default:"true"`
	RequestsPerMinute int     `yaml:"requests_per_minute" default:"100"`
	BurstSize   int           `yaml:"burst_size" default:"10"`
	CleanupInterval time.Duration `yaml:"cleanup_interval" default:"5m"`
}

// GovernanceConfig contains governance engine configuration
type GovernanceConfig struct {
	PolicyEngine   PolicyEngineConfig   `yaml:"policy_engine"`
	Moderation     ModerationConfig     `yaml:"moderation"`
	LLMAdapters    []LLMAdapterConfig   `yaml:"llm_adapters"`
	Guardrails     GuardrailsConfig     `yaml:"guardrails"`
	AuditSettings  AuditConfig          `yaml:"audit"`
}

// PolicyEngineConfig contains OPA configuration
type PolicyEngineConfig struct {
	Type        string            `yaml:"type" default:"opa"`
	PolicyDir   string            `yaml:"policy_dir" default:"./policies"`
	DataDir     string            `yaml:"data_dir" default:"./data"`
	BundleMode  bool              `yaml:"bundle_mode" default:"false"`
	BundleURL   string            `yaml:"bundle_url"`
	Plugins     map[string]interface{} `yaml:"plugins"`
}

// ModerationConfig contains moderation settings
type ModerationConfig struct {
	Enabled   bool                    `yaml:"enabled" default:"true"`
	Providers []ModerationProvider    `yaml:"providers"`
	Fallback  string                  `yaml:"fallback" default:"allow"`
	Timeout   time.Duration           `yaml:"timeout" default:"10s"`
}

// ModerationProvider represents a moderation service
type ModerationProvider struct {
	Name     string                 `yaml:"name"`
	Type     string                 `yaml:"type"` // "openai", "cohere", "huggingface", "local"
	Enabled  bool                   `yaml:"enabled" default:"true"`
	Priority int                    `yaml:"priority" default:"1"`
	Config   map[string]interface{} `yaml:"config"`
}

// LLMAdapterConfig contains LLM adapter configuration
type LLMAdapterConfig struct {
	Name     string                 `yaml:"name"`
	Type     string                 `yaml:"type"` // "openai", "anthropic", "local", "ollama"
	Enabled  bool                   `yaml:"enabled" default:"true"`
	Config   map[string]interface{} `yaml:"config"`
}

// GuardrailsConfig contains guardrail settings
type GuardrailsConfig struct {
	Enabled        bool                   `yaml:"enabled" default:"true"`
	InputFilters   []GuardrailFilter      `yaml:"input_filters"`
	OutputFilters  []GuardrailFilter      `yaml:"output_filters"`
	SchemaValidation bool                 `yaml:"schema_validation" default:"true"`
	CustomRules    map[string]interface{} `yaml:"custom_rules"`
}

// GuardrailFilter represents a single guardrail filter
type GuardrailFilter struct {
	Name     string                 `yaml:"name"`
	Type     string                 `yaml:"type"`
	Enabled  bool                   `yaml:"enabled" default:"true"`
	Config   map[string]interface{} `yaml:"config"`
}

// AuditConfig contains audit and logging settings
type AuditConfig struct {
	Enabled       bool          `yaml:"enabled" default:"true"`
	LogLevel      string        `yaml:"log_level" default:"info"`
	RetentionDays int           `yaml:"retention_days" default:"90"`
	Destinations  []AuditDest   `yaml:"destinations"`
	Sampling      SamplingConfig `yaml:"sampling"`
}

// AuditDest represents an audit destination
type AuditDest struct {
	Type   string                 `yaml:"type"` // "file", "elasticsearch", "s3", "webhook"
	Config map[string]interface{} `yaml:"config"`
}

// SamplingConfig contains audit sampling settings
type SamplingConfig struct {
	Enabled    bool    `yaml:"enabled" default:"false"`
	Rate       float64 `yaml:"rate" default:"0.1"`
	MaxPerSecond int   `yaml:"max_per_second" default:"100"`
}

// SecurityConfig contains security settings
type SecurityConfig struct {
	TLS  TLSConfig  `yaml:"tls"`
	Auth AuthConfig `yaml:"auth"`
}

// TLSConfig contains TLS configuration
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled" default:"false"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	MinVersion string `yaml:"min_version" default:"1.2"`
}

// AuthConfig contains authentication configuration
type AuthConfig struct {
	Enabled   bool              `yaml:"enabled" default:"false"`
	Type      string            `yaml:"type" default:"jwt"` // "jwt", "oauth2", "apikey"
	Config    map[string]interface{} `yaml:"config"`
	RBAC      RBACConfig        `yaml:"rbac"`
}

// RBACConfig contains role-based access control settings
type RBACConfig struct {
	Enabled bool                   `yaml:"enabled" default:"false"`
	Roles   map[string]RoleConfig  `yaml:"roles"`
}

// RoleConfig defines a role and its permissions
type RoleConfig struct {
	Permissions []string `yaml:"permissions"`
	Resources   []string `yaml:"resources"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level      string        `yaml:"level" default:"info"`
	Format     string        `yaml:"format" default:"json"`
	Output     []string      `yaml:"output" default:"[\"stdout\"]"`
	File       FileLogConfig `yaml:"file"`
	Structured bool          `yaml:"structured" default:"true"`
}

// FileLogConfig contains file logging settings
type FileLogConfig struct {
	Path       string `yaml:"path" default:"./logs/governor.log"`
	MaxSize    int    `yaml:"max_size" default:"100"`    // MB
	MaxBackups int    `yaml:"max_backups" default:"3"`
	MaxAge     int    `yaml:"max_age" default:"28"`      // days
	Compress   bool   `yaml:"compress" default:"true"`
}

// StorageConfig contains storage configuration
type StorageConfig struct {
	Type   string                 `yaml:"type" default:"file"` // "file", "sqlite", "postgres", "redis"
	Config map[string]interface{} `yaml:"config"`
}

// MonitoringConfig contains monitoring and metrics configuration
type MonitoringConfig struct {
	Enabled    bool              `yaml:"enabled" default:"true"`
	Prometheus PrometheusConfig  `yaml:"prometheus"`
	Health     HealthConfig      `yaml:"health"`
	Tracing    TracingConfig     `yaml:"tracing"`
}

// PrometheusConfig contains Prometheus metrics configuration
type PrometheusConfig struct {
	Enabled bool   `yaml:"enabled" default:"true"`
	Path    string `yaml:"path" default:"/metrics"`
	Port    int    `yaml:"port" default:"9090"`
}

// HealthConfig contains health check configuration
type HealthConfig struct {
	Enabled  bool   `yaml:"enabled" default:"true"`
	Path     string `yaml:"path" default:"/health"`
	Detailed bool   `yaml:"detailed" default:"true"`
}

// TracingConfig contains distributed tracing configuration
type TracingConfig struct {
	Enabled  bool   `yaml:"enabled" default:"false"`
	Provider string `yaml:"provider" default:"jaeger"`
	Endpoint string `yaml:"endpoint"`
	ServiceName string `yaml:"service_name" default:"universal-ai-governor"`
}

// Load reads and parses the configuration file
func Load(path string) (*Config, error) {
	// Set default config
	config := &Config{
		Server: ServerConfig{
			Mode:         "development",
			ReadTimeout:  30,
			WriteTimeout: 30,
			IdleTimeout:  120,
			CORS: CORSConfig{
				Enabled: true,
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

	// Read config file if it exists
	if _, err := os.Stat(path); err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	// Override with environment variables
	if err := loadFromEnv(config); err != nil {
		return nil, fmt.Errorf("failed to load environment variables: %w", err)
	}

	return config, nil
}

// loadFromEnv loads configuration from environment variables
func loadFromEnv(config *Config) error {
	// Server configuration
	if port := os.Getenv("GOVERNOR_PORT"); port != "" {
		// Port is handled in main.go via flag
	}
	
	if mode := os.Getenv("GOVERNOR_MODE"); mode != "" {
		config.Server.Mode = mode
	}

	// Security configuration
	if tlsEnabled := os.Getenv("GOVERNOR_TLS_ENABLED"); tlsEnabled == "true" {
		config.Security.TLS.Enabled = true
	}
	
	if certFile := os.Getenv("GOVERNOR_TLS_CERT"); certFile != "" {
		config.Security.TLS.CertFile = certFile
	}
	
	if keyFile := os.Getenv("GOVERNOR_TLS_KEY"); keyFile != "" {
		config.Security.TLS.KeyFile = keyFile
	}

	// Logging configuration
	if logLevel := os.Getenv("GOVERNOR_LOG_LEVEL"); logLevel != "" {
		config.Logging.Level = logLevel
	}

	return nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Validate TLS configuration
	if c.Security.TLS.Enabled {
		if c.Security.TLS.CertFile == "" || c.Security.TLS.KeyFile == "" {
			return fmt.Errorf("TLS enabled but cert_file or key_file not specified")
		}
	}

	// Validate policy engine configuration
	if c.Governance.PolicyEngine.Type == "" {
		return fmt.Errorf("policy engine type must be specified")
	}

	// Validate logging configuration
	validLogLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true, "fatal": true,
	}
	if !validLogLevels[c.Logging.Level] {
		return fmt.Errorf("invalid log level: %s", c.Logging.Level)
	}

	return nil
}
