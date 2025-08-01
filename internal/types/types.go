package types

import (
	"time"
)

// GovernanceRequest represents a request for AI governance
type GovernanceRequest struct {
	ID         string                 `json:"id"`
	Content    string                 `json:"content"`
	Context    map[string]interface{} `json:"context"`
	Timestamp  time.Time              `json:"timestamp"`
	RequestID  string                 `json:"request_id"`
	UserID     string                 `json:"user_id"`
	LLMAdapter string                 `json:"llm_adapter"`
	LLMOptions map[string]interface{} `json:"llm_options"`
	Prompt     string                 `json:"prompt"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// GovernanceResponse represents the response from the governance engine
type GovernanceResponse struct {
	RequestID   string                 `json:"request_id"`
	Status      string                 `json:"status"`
	Reason      string                 `json:"reason,omitempty"`
	LLMResponse string                 `json:"llm_response,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

// MetricsSnapshot represents a snapshot of metrics
type MetricsSnapshot struct {
	TotalRequests    uint64    `json:"total_requests"`
	BlockedRequests  uint64    `json:"blocked_requests"`
	AllowedRequests  uint64    `json:"allowed_requests"`
	ErrorRequests    uint64    `json:"error_requests"`
	ProcessingTimeMs float64   `json:"processing_time_ms"`
	AverageProcessingTime float64 `json:"average_processing_time"`
	RequestsPerSecond float64 `json:"requests_per_second"`
	BlockedByComponent map[string]uint64 `json:"blocked_by_component"`
	ErrorsByComponent  map[string]uint64 `json:"errors_by_component"`
	Timestamp        time.Time `json:"timestamp"`
}

const (
	StatusProcessing = "processing"
	StatusError      = "error"
	StatusBlocked    = "blocked"
	StatusAllowed    = "allowed"
)

// AuditEntry represents an entry in the audit log
type AuditEntry struct {
	ID             string                 `json:"id"`
	Timestamp      time.Time              `json:"timestamp"`
	Action         string                 `json:"action"`
	Details        map[string]interface{} `json:"details"`
	UserID         string                 `json:"user_id"`
	RequestID      string                 `json:"request_id"`
	InputPrompt    string                 `json:"input_prompt"`
	OutputResponse string                 `json:"output_response"`
	Status         string                 `json:"status"`
	ProcessingTime time.Duration          `json:"processing_time_ms"`
	Metadata       map[string]interface{} `json:"metadata"`
	Steps          []AuditStep            `json:"steps"`
}

// AuditStep represents a step in the audit trail
type AuditStep struct {
	Step      string        `json:"step"`
	Timestamp time.Time     `json:"timestamp"`
	Result    interface{}   `json:"result"`
}

// SafetyResult represents the result of safety checks
type SafetyResult struct {
	Safe       bool     `json:"safe"`
	Confidence float64  `json:"confidence"`
	Reasons    []string `json:"reasons"`
}

// GovernanceDecision represents the result of governance evaluation
type GovernanceDecision struct {
	RequestID     string    `json:"request_id"`
	Decision      string    `json:"decision"` // "allow", "block", "review"
	Confidence    float64   `json:"confidence"`
	Reason        string    `json:"reason"`
	PolicyApplied string    `json:"policy_applied"`
	Timestamp     time.Time `json:"timestamp"`
}

// GuardrailResult represents the result of guardrail evaluation
type GuardrailResult struct {
	Valid             bool                   `json:"valid"`
	Reason            string                 `json:"reason"`
	TransformedInput  string                 `json:"transformed_input,omitempty"`
	TransformedOutput string                 `json:"transformed_output,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

type AuthResult struct {
	Authenticated bool                   `json:"authenticated"`
	Authorized    bool                   `json:"authorized"`
	UserID        string                 `json:"user_id,omitempty"`
	Roles         []string               `json:"roles,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// PolicyConfig represents configuration for a governance policy
type PolicyConfig struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Rules       string                 `json:"rules"`
	Enabled     bool                   `json:"enabled"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PolicyDocument represents a policy document
type PolicyDocument struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

// LLMRequest represents a request to an LLM adapter
type LLMRequest struct {
	ID       string                 `json:"id"`
	Model    string                 `json:"model"`
	Messages []Message              `json:"messages"`
	Options  map[string]interface{} `json:"options"`
	Prompt   string                 `json:"prompt"` // for compatibility
}

// LLMResponse represents a response from an LLM adapter
type LLMResponse struct {
	ID           string                 `json:"id"`
	Content      string                 `json:"content"`
	Usage        Usage                  `json:"usage"`
	Error        *string                `json:"error,omitempty"`
	Model        string                 `json:"model"`
	TokensUsed   int                    `json:"tokens_used"`
	FinishReason string                 `json:"finish_reason"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// Message represents a chat message
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Usage represents token usage information
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ComponentHealth represents the health status of a component
type ComponentHealth struct {
	Status    string                 `json:"status"`
	Message   string                 `json:"message"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
	Components map[string]ComponentHealth `json:"components,omitempty"`
}

// Health status constants
const (
	HealthStatusHealthy   = "healthy"
	HealthStatusUnhealthy = "unhealthy"
	HealthStatusDegraded  = "degraded"
)

// ModerationResult represents the result of content moderation
type ModerationResult struct {
	Flagged    bool                   `json:"flagged"`
	Categories map[string]bool        `json:"categories"`
	Scores     map[string]float64     `json:"scores"`
	Details    map[string]interface{} `json:"details"`
	Blocked    bool                   `json:"blocked"`
	Confidence float64                `json:"confidence"`
	Metadata   map[string]interface{} `json:"metadata"`
	Reason     string                 `json:"reason"`
}

// PolicyResult represents the result of policy evaluation
type PolicyResult struct {
	Allow      bool                   `json:"allow"`
	Allowed    bool                   `json:"allowed"` // alias for Allow
	Reason     string                 `json:"reason"`
	Confidence float64                `json:"confidence"`
	Metadata   map[string]interface{} `json:"metadata"`
	Policies   []string               `json:"policies"`
}

// LLMAdapterType represents the type of LLM adapter
type LLMAdapterType string

const (
	LLMAdapterTypeOpenAI      LLMAdapterType = "openai"
	LLMAdapterTypeOllama      LLMAdapterType = "ollama"
	LLMAdapterTypeAnthropic   LLMAdapterType = "anthropic"
	LLMAdapterTypeLocal       LLMAdapterType = "local"
	LLMAdapterTypeHuggingFace LLMAdapterType = "huggingface"
)

// ModerationProviderType represents the type of moderation provider
type ModerationProviderType string

const (
	ModerationProviderOpenAI      ModerationProviderType = "openai"
	ModerationProviderCohere      ModerationProviderType = "cohere"
	ModerationProviderHuggingFace ModerationProviderType = "huggingface"
	ModerationProviderLocal       ModerationProviderType = "local"
	ModerationProviderCustom      ModerationProviderType = "custom"
)

// ModerationProviderConfig represents configuration for a moderation provider
type ModerationProviderConfig struct {
	Name     string                 `json:"name"`
	Type     ModerationProviderType `json:"type"`
	Enabled  bool                   `json:"enabled"`
	Priority int                    `json:"priority"`
	Config   map[string]interface{} `json:"config"`
}

// PolicyEngineType represents the type of policy engine
type PolicyEngineType string

const (
	PolicyEngineTypeRego PolicyEngineType = "rego"
	PolicyEngineTypeCEL  PolicyEngineType = "cel"
)

// PolicyEngineConfig represents configuration for a policy engine
type PolicyEngineConfig struct {
	Name    string           `json:"name"`
	Type    PolicyEngineType `json:"type"`
	Enabled bool             `json:"enabled"`
	Config  map[string]interface{} `json:"config"`
}

// AuditSinkType represents the type of audit sink
type AuditSinkType string

const (
	AuditSinkTypeFile   AuditSinkType = "file"
	AuditSinkTypeStdout AuditSinkType = "stdout"
	AuditSinkTypeKafka  AuditSinkType = "kafka"
	AuditSinkTypeHTTP   AuditSinkType = "http"
)

// AuditSinkConfig represents configuration for an audit sink
type AuditSinkConfig struct {
	Name    string        `json:"name"`
	Type    AuditSinkType `json:"type"`
	Enabled bool          `json:"enabled"`
	Config  map[string]interface{} `json:"config"`
}

// SecurityModuleType represents the type of security module
type SecurityModuleType string

const (
	SecurityModuleTypeTLS SecurityModuleType = "tls"
	SecurityModuleTypeJWT SecurityModuleType = "jwt"
)

// SecurityModuleConfig represents configuration for a security module
type SecurityModuleConfig struct {
	Name    string             `json:"name"`
	Type    SecurityModuleType `json:"type"`
	Enabled bool               `json:"enabled"`
	Config  map[string]interface{} `json:"config"`
}

// HardwareSecurityModuleType represents the type of hardware security module
type HardwareSecurityModuleType string

const (
	HardwareSecurityModuleTypeTPM   HardwareSecurityModuleType = "tpm"
	HardwareSecurityModuleTypeHSM   HardwareSecurityModuleType = "hsm"
	HardwareSecurityModuleTypeSE    HardwareSecurityModuleType = "secure_enclave"
)

// HardwareSecurityModuleConfig represents configuration for a hardware security module
type HardwareSecurityModuleConfig struct {
	Name    string                     `json:"name"`
	Type    HardwareSecurityModuleType `json:"type"`
	Enabled bool                       `json:"enabled"`
	Config  map[string]interface{}     `json:"config"`
}

// AdversarialTestingConfig represents configuration for adversarial testing
type AdversarialTestingConfig struct {
	Enabled bool                   `json:"enabled"`
	Config  map[string]interface{} `json:"config"`
}

// FuzzingSupportConfig represents configuration for fuzzing support
type FuzzingSupportConfig struct {
	Enabled bool                   `json:"enabled"`
	Config  map[string]interface{} `json:"config"`
}

// FaultInjectionConfig represents configuration for fault injection
type FaultInjectionConfig struct {
	Enabled bool                   `json:"enabled"`
	Config  map[string]interface{} `json:"config"`
}

// ChaosTestingConfig represents configuration for chaos testing
type ChaosTestingConfig struct {
	Enabled bool                   `json:"enabled"`
	Config  map[string]interface{} `json:"config"`
}

// RBACConfig represents configuration for Role-Based Access Control
type RBACConfig struct {
	Enabled bool                   `json:"enabled"`
	Config  map[string]interface{} `json:"config"`
}

// PermissionMatrixConfig represents configuration for permission matrix
type PermissionMatrixConfig struct {
	Enabled bool                   `json:"enabled"`
	Config  map[string]interface{} `json:"config"`
}

// StabilityTestingConfig represents configuration for stability testing
type StabilityTestingConfig struct {
	Enabled bool                   `json:"enabled"`
	Config  map[string]interface{} `json:"config"`
}

// MemoryProfilingConfig represents configuration for memory profiling
type MemoryProfilingConfig struct {
	Enabled bool                   `json:"enabled"`
	Config  map[string]interface{} `json:"config"`
}

// LoadTestingConfig represents configuration for load testing
type LoadTestingConfig struct {
	Enabled bool                   `json:"enabled"`
	Config  map[string]interface{} `json:"config"`
}

// MetricsConfig represents configuration for metrics
type MetricsConfig struct {
	Enabled bool                   `json:"enabled"`
	Config  map[string]interface{} `json:"config"`
}

// FIPSComplianceConfig represents configuration for FIPS compliance
type FIPSComplianceConfig struct {
	Enabled bool                   `json:"enabled"`
	Config  map[string]interface{} `json:"config"`
}

// ModerationProvider represents a moderation provider
type ModerationProvider struct {
	Name     string                 `json:"name"`
	Type     ModerationProviderType `json:"type"`
	Enabled  bool                   `json:"enabled"`
	Priority int                    `json:"priority"`
	Config   map[string]interface{} `json:"config"`
}

// ModerationConfig represents the overall moderation configuration
type ModerationConfig struct {
	Enabled   bool                   `json:"enabled"`
	Providers []ModerationProvider   `json:"providers"`
	Fallback  string                 `json:"fallback"`
	Timeout   time.Duration          `json:"timeout"`
	Config    map[string]interface{} `json:"config"`
}

// GovernanceConfig represents the overall governance configuration
type GovernanceConfig struct {
	Enabled          bool                         `json:"enabled"`
	Policy           PolicyEngineConfig           `json:"policy_engine"`
	Audit            AuditSinkConfig              `json:"audit_sink"`
	Security         SecurityModuleConfig         `json:"security_module"`
	Moderation       ModerationConfig             `json:"moderation"`
	HardwareSecurity HardwareSecurityModuleConfig `json:"hardware_security"`
	AdversarialTesting AdversarialTestingConfig     `json:"adversarial_testing"`
	FuzzingSupport   FuzzingSupportConfig         `json:"fuzzing_support"`
	FaultInjection   FaultInjectionConfig         `json:"fault_injection"`
	ChaosTesting     ChaosTestingConfig           `json:"chaos_testing"`
	RBAC             RBACConfig                   `json:"rbac"`
	PermissionMatrix PermissionMatrixConfig       `json:"permission_matrix"`
	StabilityTesting StabilityTestingConfig       `json:"stability_testing"`
	MemoryProfiling  MemoryProfilingConfig        `json:"memory_profiling"`
	LoadTesting      LoadTestingConfig            `json:"load_testing"`
	Metrics          MetricsConfig                `json:"metrics"`
	FIPSCompliance   FIPSComplianceConfig         `json:"fips_compliance"`
	Config           map[string]interface{}       `json:"config"`
}
