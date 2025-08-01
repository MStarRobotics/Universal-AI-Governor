//! Audit logging for Universal AI Governor
//!
//! This module provides robust audit logging capabilities for the Universal AI Governor.
//! It is a cornerstone for achieving the "humanization effect" in AI governance by ensuring
//! transparency, accountability, and traceability of all AI-related decisions and actions.
//! By meticulously recording every event, it enables "AI bypass" of opaque black-box behaviors,
//! allowing for forensic analysis, compliance verification, and a deep understanding of how
//! AI systems operate under governance.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a single audit log entry within the Universal AI Governor.
/// Each entry captures critical information about an event, providing a detailed
/// and immutable record for accountability and analysis. This granular logging
/// is essential for building trust in AI systems and for debugging complex
/// interactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    /// A unique identifier for the audit log entry, ensuring each event is distinct.
    pub id: String,
    /// The identifier of the user or entity that initiated the action, crucial for traceability.
    pub user_id: String,
    /// The specific action that was performed (e.g., "policy_evaluation", "model_inference").
    pub action: String,
    /// The resource or component affected by the action (e.g., "policy:1", "llm_adapter:openai").
    pub resource: String,
    /// A flexible map for storing additional, context-specific details about the event.
    pub details: HashMap<String, serde_json::Value>,
    /// The timestamp when the event occurred, recorded in UTC for consistency.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// The IP address from which the action originated, if available, for network-level traceability.
    pub ip_address: Option<String>,
}

/// Manages the collection and retrieval of audit logs within the Universal AI Governor.
/// This component is responsible for maintaining the integrity of the audit trail,
/// which is vital for compliance, security, and understanding the operational
/// history of the AI governance system.
#[derive(Debug)]
pub struct AuditLogger {
    logs: Vec<AuditLog>,
}

impl AuditLogger {
    /// Creates a new, empty instance of the `AuditLogger`.
    /// This initializes the in-memory log store, ready to capture events.
    pub fn new() -> Self {
        Self { logs: Vec::new() }
    }

    /// Logs a new action, creating an `AuditLog` entry and adding it to the logger's store.
    /// This function is the primary interface for recording significant events within the system,
    /// ensuring that every critical operation is documented.
    pub fn log_action(
        &mut self,
        user_id: String,
        action: String,
        resource: String,
        details: HashMap<String, serde_json::Value>,
        ip_address: Option<String>,
    ) {
        let log = AuditLog {
            id: uuid::Uuid::new_v4().to_string(), // Generate a unique ID for the log entry.
            user_id,
            action,
            resource,
            details,
            timestamp: chrono::Utc::now(), // Record the current UTC timestamp.
            ip_address,
        };

        self.logs.push(log);
    }

    /// Retrieves all stored audit logs.
    /// This function provides access to the historical record of AI governance activities,
    /// enabling comprehensive analysis and reporting.
    pub fn get_logs(&self) -> &[AuditLog] {
        &self.logs
    }
}

impl Default for AuditLogger {
    /// Provides a default instance of `AuditLogger`.
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_logger() {
        let mut logger = AuditLogger::new();

        logger.log_action(
            "user1".to_string(),
            "login".to_string(),
            "system".to_string(),
            HashMap::new(),
            Some("127.0.0.1".to_string()),
        );

        assert_eq!(logger.get_logs().len(), 1);
        let log = &logger.get_logs()[0];
        assert!(!log.id.is_empty());
        assert_eq!(log.user_id, "user1");
        assert_eq!(log.action, "login");
        assert_eq!(log.resource, "system");
        assert!(log.details.is_empty());
        assert!(log.ip_address.is_some());
        assert_eq!(log.ip_address.as_ref().unwrap(), "127.0.0.1");
    }
}
