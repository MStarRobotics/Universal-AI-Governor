package types

import (
	"time"
)

// GovernanceRequest represents a request to the governance engine
type GovernanceRequest struct {
	RequestID  string                 `json:"request_id,omitempty"`
	UserID     string                 `json:"user_id"`
	Prompt     string                 `json:"prompt"`
	Context    map[string]interface{} `json:"context,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	LLMAdapter string                 `json:"llm_adapter,omitempty"`
	LLMOptions map[string]interface{} `json:"llm_options,omitempty"`
}

// GovernanceResponse represents a response from the governance engine
type GovernanceResponse struct {
	RequestID   string                 `json:"request_id"`
	Status      ResponseStatus         `json:"status"`
	LLMResponse string                 `json:"llm_response,omitempty"`
	Reason      string                 `json:"reason,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ResponseStatus represents the status of a governance response
type ResponseStatus string

const (
	StatusAllowed    ResponseStatus = "allowed"
	StatusBlocked    ResponseStatus = "blocked"
	StatusError      ResponseStatus = "error"
	StatusProcessing ResponseStatus = "processing"
)

// LLMRequest represents a request to an LLM adapter
type LLMRequest struct {
	Prompt  string                 `json:"prompt"`
	Context map[string]interface{} `json:"context,omitempty"`
	Options map[string]interface{} `json:"options,omitempty"`
	UserID  string                 `json:"user_id,omitempty"`
}

// LLMResponse represents a response from an LLM adapter
type LLMResponse struct {
	Content      string                 `json:"content"`
	Model        string                 `json:"model"`
	TokensUsed   int                    `json:"tokens_used"`
	FinishReason string                 `json:"finish_reason"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// ModerationResult represents the result of content moderation
type ModerationResult struct {
	Blocked    bool                   `json:"blocked"`
	Reason     string                 `json:"reason,omitempty"`
	Confidence float64                `json:"confidence"`
	Categories []string               `json:"categories,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// PolicyResult represents the result of policy evaluation
type PolicyResult struct {
	Allowed   bool                   `json:"allowed"`
	Reason    string                 `json:"reason,omitempty"`
	Policies  []string               `json:"policies,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// GuardrailResult represents the result of guardrail validation
type GuardrailResult struct {
	Valid             bool                   `json:"valid"`
	Reason            string                 `json:"reason,omitempty"`
	TransformedInput  string                 `json:"transformed_input,omitempty"`
	TransformedOutput string                 `json:"transformed_output,omitempty"`
	Violations        []GuardrailViolation   `json:"violations,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

// GuardrailViolation represents a specific guardrail violation
type GuardrailViolation struct {
	Rule        string  `json:"rule"`
	Severity    string  `json:"severity"`
	Message     string  `json:"message"`
	Confidence  float64 `json:"confidence"`
	Location    string  `json:"location,omitempty"`
}

// AuditEntry represents an audit log entry
type AuditEntry struct {
	RequestID      string                 `json:"request_id"`
	UserID         string                 `json:"user_id"`
	Timestamp      time.Time              `json:"timestamp"`
	InputPrompt    string                 `json:"input_prompt"`
	OutputResponse string                 `json:"output_response,omitempty"`
	Status         string                 `json:"status"`
	ProcessingTime time.Duration          `json:"processing_time"`
	Steps          []AuditStep            `json:"steps"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// AuditStep represents a single step in the governance pipeline
type AuditStep struct {
	Step      string      `json:"step"`
	Timestamp time.Time   `json:"timestamp"`
	Result    interface{} `json:"result"`
}

// HealthStatus represents the health status of a component
type HealthStatus struct {
	Status     string                       `json:"status"`
	Timestamp  time.Time                    `json:"timestamp"`
	Components map[string]ComponentHealth   `json:"components,omitempty"`
	Metadata   map[string]interface{}       `json:"metadata,omitempty"`
}

// ComponentHealth represents the health of a specific component
type ComponentHealth struct {
	Status    string                 `json:"status"`
	Message   string                 `json:"message,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// MetricsSnapshot represents a snapshot of system metrics
type MetricsSnapshot struct {
	Timestamp           time.Time         `json:"timestamp"`
	TotalRequests       int64             `json:"total_requests"`
	AllowedRequests     int64             `json:"allowed_requests"`
	BlockedRequests     int64             `json:"blocked_requests"`
	ErrorRequests       int64             `json:"error_requests"`
	AverageProcessingTime time.Duration   `json:"average_processing_time"`
	RequestsPerSecond   float64           `json:"requests_per_second"`
	BlockedByComponent  map[string]int64  `json:"blocked_by_component"`
	ErrorsByComponent   map[string]int64  `json:"errors_by_component"`
}

// PolicyDocument represents a policy document
type PolicyDocument struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Description string                 `json:"description"`
	Rules       []PolicyRule           `json:"rules"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// PolicyRule represents a single policy rule
type PolicyRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Condition   string                 `json:"condition"`
	Action      string                 `json:"action"`
	Priority    int                    `json:"priority"`
	Enabled     bool                   `json:"enabled"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// User represents a user in the system
type User struct {
	ID          string                 `json:"id"`
	Username    string                 `json:"username"`
	Email       string                 `json:"email,omitempty"`
	Roles       []string               `json:"roles"`
	Permissions []string               `json:"permissions"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// Session represents a user session
type Session struct {
	ID        string                 `json:"id"`
	UserID    string                 `json:"user_id"`
	Token     string                 `json:"token"`
	ExpiresAt time.Time              `json:"expires_at"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// Configuration types for different components

// LLMAdapterConfig represents configuration for an LLM adapter
type LLMAdapterConfig struct {
	Name     string                 `json:"name"`
	Type     string                 `json:"type"`
	Enabled  bool                   `json:"enabled"`
	Config   map[string]interface{} `json:"config"`
}

// ModerationProviderConfig represents configuration for a moderation provider
type ModerationProviderConfig struct {
	Name     string                 `json:"name"`
	Type     string                 `json:"type"`
	Enabled  bool                   `json:"enabled"`
	Priority int                    `json:"priority"`
	Config   map[string]interface{} `json:"config"`
}

// GuardrailConfig represents configuration for a guardrail
type GuardrailConfig struct {
	Name    string                 `json:"name"`
	Type    string                 `json:"type"`
	Enabled bool                   `json:"enabled"`
	Config  map[string]interface{} `json:"config"`
}

// Error types

// GovernanceError represents a governance-specific error
type GovernanceError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Component string `json:"component"`
	RequestID string `json:"request_id,omitempty"`
}

func (e *GovernanceError) Error() string {
	return fmt.Sprintf("[%s] %s: %s", e.Component, e.Code, e.Message)
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   string `json:"value,omitempty"`
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
}

// Constants for various components

// Policy actions
const (
	PolicyActionAllow = "allow"
	PolicyActionBlock = "block"
	PolicyActionWarn  = "warn"
	PolicyActionLog   = "log"
)

// Moderation categories
const (
	ModerationCategoryHate       = "hate"
	ModerationCategoryViolence   = "violence"
	ModerationCategorySexual     = "sexual"
	ModerationCategoryToxicity   = "toxicity"
	ModerationCategorySpam       = "spam"
	ModerationCategoryPII        = "pii"
	ModerationCategoryProfanity  = "profanity"
)

// Guardrail types
const (
	GuardrailTypeSchema    = "schema"
	GuardrailTypeRegex     = "regex"
	GuardrailTypeLength    = "length"
	GuardrailTypeFormat    = "format"
	GuardrailTypeContent   = "content"
	GuardrailTypeCustom    = "custom"
)

// LLM adapter types
const (
	LLMAdapterTypeOpenAI    = "openai"
	LLMAdapterTypeAnthropic = "anthropic"
	LLMAdapterTypeLocal     = "local"
	LLMAdapterTypeOllama    = "ollama"
	LLMAdapterTypeHuggingFace = "huggingface"
)

// Moderation provider types
const (
	ModerationProviderOpenAI      = "openai"
	ModerationProviderCohere      = "cohere"
	ModerationProviderHuggingFace = "huggingface"
	ModerationProviderLocal       = "local"
	ModerationProviderCustom      = "custom"
)

// Health status values
const (
	HealthStatusHealthy  = "healthy"
	HealthStatusDegraded = "degraded"
	HealthStatusUnhealthy = "unhealthy"
)

// Audit log levels
const (
	AuditLevelDebug = "debug"
	AuditLevelInfo  = "info"
	AuditLevelWarn  = "warn"
	AuditLevelError = "error"
)

// Helper functions

// NewGovernanceError creates a new governance error
func NewGovernanceError(code, message, component string) *GovernanceError {
	return &GovernanceError{
		Code:      code,
		Message:   message,
		Component: component,
	}
}

// NewValidationError creates a new validation error
func NewValidationError(field, message string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Message: message,
	}
}

// IsBlocked checks if a response status indicates blocking
func (s ResponseStatus) IsBlocked() bool {
	return s == StatusBlocked
}

// IsError checks if a response status indicates an error
func (s ResponseStatus) IsError() bool {
	return s == StatusError
}

// IsSuccess checks if a response status indicates success
func (s ResponseStatus) IsSuccess() bool {
	return s == StatusAllowed
}
