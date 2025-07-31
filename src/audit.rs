//! Audit logging for Universal AI Governor

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    /// Log entry ID
    pub id: String,
    /// User ID
    pub user_id: String,
    /// Action performed
    pub action: String,
    /// Resource affected
    pub resource: String,
    /// Additional details
    pub details: HashMap<String, serde_json::Value>,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// IP address
    pub ip_address: Option<String>,
}

/// Audit logger
#[derive(Debug)]
pub struct AuditLogger {
    logs: Vec<AuditLog>,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new() -> Self {
        Self {
            logs: Vec::new(),
        }
    }
    
    /// Log an action
    pub fn log_action(
        &mut self,
        user_id: String,
        action: String,
        resource: String,
        details: HashMap<String, serde_json::Value>,
        ip_address: Option<String>,
    ) {
        let log = AuditLog {
            id: uuid::Uuid::new_v4().to_string(),
            user_id,
            action,
            resource,
            details,
            timestamp: chrono::Utc::now(),
            ip_address,
        };
        
        self.logs.push(log);
    }
    
    /// Get all logs
    pub fn get_logs(&self) -> &[AuditLog] {
        &self.logs
    }
}

impl Default for AuditLogger {
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
    }
}
