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

// SafetyResult represents the result of safety checks
type SafetyResult struct {
	Safe       bool     `json:"safe"`
	Confidence float64  `json:"confidence"`
	Reasons    []string `json:"reasons"`
}

// AuditEntry represents an entry in the audit log
type AuditEntry struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Action    string                 `json:"action"`
	Details   map[string]interface{} `json:"details"`
	UserID    string                 `json:"user_id"`
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
