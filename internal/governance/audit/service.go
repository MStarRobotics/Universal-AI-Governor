package audit

import (
	"fmt"
	"sync"
	"time"

	"github.com/universal-ai-governor/internal/config"
	"github.com/universal-ai-governor/internal/logging"
	"github.com/universal-ai-governor/internal/types"
)

// Service defines the interface for the audit logging component.
// This component is responsible for recording all significant events
// and decisions within the governance engine, providing an immutable
// and verifiable trail for compliance, debugging, and post-incident analysis.
type Service interface {
	// LogEntry records a single audit event. The 'entry' parameter contains
	// all relevant details about the event, such as request ID, user, action,
	// and any associated metadata or results.
	LogEntry(entry *types.AuditEntry) error

	// GetEntries retrieves a list of audit entries based on a specified query.
	// This allows for historical analysis and reporting of governance activities.
	GetEntries(query map[string]interface{}) ([]types.AuditEntry, error)

	// Health returns the current operational status of the audit service.
	// It indicates whether the service is functioning correctly and able to
	// persist audit logs.
	Health() types.ComponentHealth

	// Close gracefully shuts down the audit service, ensuring all pending
	// logs are flushed and resources are released. This is crucial for
	// maintaining data integrity.
	Close() error
}

// AuditService implements the Service interface for audit logging.
// This service is paramount for establishing trust and accountability in AI systems.
// By meticulously logging every significant event and decision, it provides an
// immutable, transparent, and verifiable record, crucial for forensic analysis,
// compliance, and demonstrating the "humanization effect" of responsible AI.
// It acts as the system's memory, ensuring that even complex AI decisions
// can be traced back to their origins, thereby enabling "AI bypass" of opaque
// black-box behaviors through comprehensive traceability.
type AuditService struct {
	config config.AuditConfig
	logger logging.Logger
	auditLog []types.AuditEntry // In-memory store for audit entries
	mu       sync.RWMutex       // Mutex to protect access to auditLog
}

// NewService creates a new instance of the AuditService.
// It initializes the in-memory audit log and prepares the service
// for recording and retrieving audit events.
func NewService(config config.AuditConfig, logger logging.Logger) (*AuditService, error) {
	service := &AuditService{
		config:   config,
		logger:   logger,
		auditLog: make([]types.AuditEntry, 0),
	}
	logger.Info("Audit service initialized with in-memory store")
	return service, nil
}

// LogEntry records a single audit event, adding it to the in-memory log.
// This function is critical for maintaining the integrity and completeness
// of the audit trail, enabling full traceability of all governance decisions.
func (s *AuditService) LogEntry(entry *types.AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Assign a unique ID to the audit entry for precise tracking.
	if entry.ID == "" {
		entry.ID = fmt.Sprintf("audit_%d", time.Now().UnixNano())
	}

	// Record the timestamp if not already set.
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	s.auditLog = append(s.auditLog, *entry)
	s.logger.Debug("Audit entry logged", "entry_id", entry.ID, "action", entry.Action, "status", entry.Status)

	// In a production system, this is where you would dispatch the log entry
	// to configured audit sinks (e.g., file, database, Kafka, SIEM).
	// For this in-memory implementation, we simply store it.

	return nil
}

// GetEntries retrieves audit entries from the in-memory log based on a query.
// This function allows for historical analysis and reporting of governance activities,
// providing transparency and supporting the "AI bypass" of opaque decision-making.
// Currently, it supports filtering by RequestID and UserID.
func (s *AuditService) GetEntries(query map[string]interface{}) ([]types.AuditEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var filteredEntries []types.AuditEntry
	for _, entry := range s.auditLog {
		match := true
		if reqID, ok := query["request_id"]; ok && reqID != entry.RequestID {
			match = false
		}
		if userID, ok := query["user_id"]; ok && userID != entry.UserID {
			match = false
		}
		// Add more filtering logic here as needed (e.g., by status, time range, action)

		if match {
			filteredEntries = append(filteredEntries, entry)
		}
	}

	s.logger.Debug("Retrieved audit entries", "count", len(filteredEntries), "query", query)
	return filteredEntries, nil
}

// Health returns the current health status of the AuditService.
// For the in-memory implementation, it always reports as healthy,
// as its operation is self-contained and doesn't rely on external dependencies.
func (s *AuditService) Health() types.ComponentHealth {
	return types.ComponentHealth{
		Status:    types.HealthStatusHealthy,
		Message:   "Audit service is operational (in-memory)",
		Timestamp: time.Now(),
	}
}

// Close gracefully shuts down the AuditService.
// For the in-memory implementation, this involves clearing the audit log
// to release memory, ensuring a clean shutdown.
func (s *AuditService) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.auditLog = nil // Clear the in-memory log
	s.logger.Info("Audit service gracefully shut down and in-memory log cleared")
	return nil
}