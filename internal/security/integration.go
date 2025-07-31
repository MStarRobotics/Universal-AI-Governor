package security

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/universal-ai-governor/internal/logging"
)

// SecurityOrchestrator integrates all security components
type SecurityOrchestrator struct {
	logger            logging.Logger
	enclaveProtection *EnclaveProtection
	rbacSystem        *RBACSystem
	sandboxProtection *SandboxProtection
	threatDetection   *ThreatDetectionEngine
	cryptoUtils       *CryptoUtils
	mutex             sync.RWMutex
	initialized       bool
}

// SecurityContext represents comprehensive security context
type SecurityContext struct {
	UserID            string                 `json:"user_id"`
	SessionID         string                 `json:"session_id"`
	IPAddress         string                 `json:"ip_address"`
	UserAgent         string                 `json:"user_agent"`
	RequestContent    string                 `json:"request_content"`
	GeolocationData   map[string]interface{} `json:"geolocation_data"`
	DeviceFingerprint string                 `json:"device_fingerprint"`
	Timestamp         time.Time              `json:"timestamp"`
	ThreatLevel       int                    `json:"threat_level"`
	Authenticated     bool                   `json:"authenticated"`
	Authorized        bool                   `json:"authorized"`
}

// NewSecurityOrchestrator creates a new security orchestrator
func NewSecurityOrchestrator(logger logging.Logger) (*SecurityOrchestrator, error) {
	so := &SecurityOrchestrator{
		logger:      logger,
		cryptoUtils: &CryptoUtils{},
	}

	// Initialize enclave protection
	enclaveProtection, err := NewEnclaveProtection(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize enclave protection: %w", err)
	}
	so.enclaveProtection = enclaveProtection

	// Initialize RBAC system
	so.rbacSystem = NewRBACSystem(logger)

	// Initialize sandbox protection
	sandboxProtection, err := NewSandboxProtection(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize sandbox protection: %w", err)
	}
	so.sandboxProtection = sandboxProtection

	// Initialize threat detection
	so.threatDetection = NewThreatDetectionEngine()

	so.initialized = true
	logger.Info("Security orchestrator initialized successfully")

	return so, nil
}

// ValidateSecurityContext performs comprehensive security validation
func (so *SecurityOrchestrator) ValidateSecurityContext(ctx context.Context, secCtx *SecurityContext) error {
	if !so.initialized {
		return fmt.Errorf("security orchestrator not initialized")
	}

	so.mutex.RLock()
	defer so.mutex.RUnlock()

	// 1. Verify system integrity
	if err := so.enclaveProtection.VerifyIntegrity(); err != nil {
		so.logger.Error("Integrity verification failed", "error", err)
		// Trigger automatic rollback
		if rollbackErr := so.sandboxProtection.AutoRollback("integrity_failure"); rollbackErr != nil {
			so.logger.Error("Auto-rollback failed", "error", rollbackErr)
		}
		return fmt.Errorf("integrity verification failed: %w", err)
	}

	// 2. Perform threat analysis
	threatAlert, err := so.threatDetection.AnalyzeThreat(ctx, secCtx)
	if err != nil {
		so.logger.Error("Threat analysis failed", "error", err)
		return fmt.Errorf("threat analysis failed: %w", err)
	}

	if threatAlert != nil {
		so.logger.Warn("Threat detected",
			"threat_type", threatAlert.ThreatType,
			"risk_score", threatAlert.RiskScore,
			"user_id", secCtx.UserID)

		// Handle threat based on severity
		if threatAlert.Severity >= 4 {
			// High severity - immediate action required
			return fmt.Errorf("high severity threat detected: %s", threatAlert.Description)
		}
	}

	// 3. Validate authentication if required
	if secCtx.SessionID != "" {
		if err := so.validateAuthentication(secCtx); err != nil {
			return fmt.Errorf("authentication validation failed: %w", err)
		}
		secCtx.Authenticated = true
	}

	return nil
}

// validateAuthentication validates user authentication
func (so *SecurityOrchestrator) validateAuthentication(secCtx *SecurityContext) error {
	// This would integrate with the RBAC system to validate the session
	// For demonstration, we'll perform basic validation
	if secCtx.SessionID == "" {
		return fmt.Errorf("session ID required")
	}

	if secCtx.UserID == "" {
		return fmt.Errorf("user ID required")
	}

	return nil
}

// PerformIntegrityCheck performs comprehensive system integrity check
func (so *SecurityOrchestrator) PerformIntegrityCheck() error {
	so.logger.Info("Performing comprehensive integrity check")

	// Check enclave protection integrity
	if err := so.enclaveProtection.VerifyIntegrity(); err != nil {
		return fmt.Errorf("enclave integrity check failed: %w", err)
	}

	// Additional integrity checks would go here
	so.logger.Info("Comprehensive integrity check completed successfully")
	return nil
}

// GetSecurityStatus returns overall security status
func (so *SecurityOrchestrator) GetSecurityStatus() map[string]interface{} {
	status := map[string]interface{}{
		"initialized":        so.initialized,
		"enclave_protection": so.enclaveProtection != nil,
		"rbac_system":        so.rbacSystem != nil,
		"sandbox_protection": so.sandboxProtection != nil,
		"threat_detection":   so.threatDetection != nil,
		"timestamp":          time.Now(),
	}

	return status
}

// Close gracefully shuts down the security orchestrator
func (so *SecurityOrchestrator) Close() error {
	so.mutex.Lock()
	defer so.mutex.Unlock()

	so.logger.Info("Shutting down security orchestrator")

	var errors []error

	// Close all components
	if so.sandboxProtection != nil {
		// Sandbox protection doesn't need explicit closing in this implementation
	}

	so.initialized = false
	so.logger.Info("Security orchestrator shut down successfully")

	if len(errors) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errors)
	}

	return nil
}
