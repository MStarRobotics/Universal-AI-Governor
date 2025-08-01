package types

import (
	"time"
)

// GovernanceRequest represents a request for AI governance
type GovernanceRequest struct {
	ID        string                 `json:"id"`
	Content   string                 `json:"content"`
	Context   map[string]interface{} `json:"context"`
	Timestamp time.Time              `json:"timestamp"`
	RequestID string                 `json:"request_id"`
	UserID    string                 `json:"user_id"`
	LLMAdapter string                `json:"llm_adapter"`
	LLMOptions map[string]interface{} `json:"llm_options"`
	Prompt    string                 `json:"prompt"`
	Metadata  map[string]interface{} `json:"metadata"`
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
	TotalRequests    uint64 `json:"total_requests"`
	BlockedRequests  uint64 `json:"blocked_requests"`
	ProcessingTimeMs float64 `json:"processing_time_ms"`
	Timestamp        time.Time `json:"timestamp"`
}

const (
	StatusProcessing = "processing"
	StatusError      = "error"
	StatusBlocked    = "blocked"
	StatusAllowed    = "allowed"
)
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
}

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

// Health status constants
const (
	HealthStatusHealthy   = "healthy"
	HealthStatusUnhealthy = "unhealthy"
	HealthStatusDegraded  = "degraded"
)
// GovernanceDecision represents the result of governance evaluation
type GovernanceDecision struct {
	RequestID     string    `json:"request_id"`
	Decision      string    `json:"decision"` // "allow", "block", "review"
	Confidence    float64   `json:"confidence"`
	Reason        string    `json:"reason"`
	PolicyApplied string    `json:"policy_applied"`
	Timestamp     time.Time `json:"timestamp"`
}

// AuditEntry represents an entry in the audit log
type AuditEntry struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Action    string                 `json:"action"`
	Details   map[string]interface{} `json:"details"`
	UserID    string                 `json:"user_id"`
}

// GuardrailResult represents the result of guardrail evaluation
type GuardrailResult struct {
	Passed     bool                   `json:"passed"`
	Reason     string                 `json:"reason"`
	Confidence float64                `json:"confidence"`
	Metadata   map[string]interface{} `json:"metadata"`
}
