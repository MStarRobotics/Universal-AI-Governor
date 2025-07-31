//! Core governance engine
//! 
//! This is the heart of the Universal AI Governor. I spent a lot of time
//! thinking about the architecture here, trying to balance performance,
//! security, and maintainability.

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::{Result, Error};
use crate::config::GovernorConfig;
use crate::security::SecurityManager;
use crate::hardware::HardwareSecurityLayer;

pub mod governor;
pub mod policy_engine;
pub mod request_handler;
pub mod error;

// Re-export the main types that other modules need
pub use governor::GovernorCore;
pub use policy_engine::{PolicyEngine, PolicyDecision};
pub use request_handler::RequestHandler;
pub use error::CoreError;

/// Represents a governance request coming into the system
/// 
/// I've tried to make this generic enough to handle different types of content
/// while still being specific enough to be useful for policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceRequest {
    /// Unique identifier for this request
    pub id: Uuid,
    
    /// When this request was created
    pub timestamp: DateTime<Utc>,
    
    /// The actual content to be governed
    pub content: RequestContent,
    
    /// Additional context that might be useful for policy decisions
    pub context: RequestContext,
    
    /// Optional metadata from the client
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
}

/// Different types of content we can govern
/// 
/// Started with just text, but quickly realized we needed to handle
/// multimedia content too. The enum makes it easy to add new types later.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum RequestContent {
    Text { content: String },
    Image { data: Vec<u8>, format: String },
    Audio { data: Vec<u8>, format: String, sample_rate: Option<u32> },
    Video { data: Vec<u8>, format: String, duration: Option<f64> },
    // TODO: Add support for structured data, documents, etc.
}

/// Context information that helps with policy decisions
/// 
/// This is stuff like who's making the request, what application it's for,
/// etc. Really important for making good governance decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    /// User making the request (if known)
    pub user_id: Option<String>,
    
    /// Application or service making the request
    pub application: Option<String>,
    
    /// Session identifier
    pub session_id: Option<String>,
    
    /// IP address of the requester
    pub ip_address: Option<std::net::IpAddr>,
    
    /// User agent string
    pub user_agent: Option<String>,
    
    /// Any additional context the client wants to provide
    pub additional: std::collections::HashMap<String, serde_json::Value>,
}

/// The result of a governance decision
/// 
/// I went back and forth on whether to make this an enum or a struct.
/// Ended up with a struct because it's more flexible and easier to extend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceDecision {
    /// Unique identifier for this decision
    pub id: Uuid,
    
    /// The request this decision is for
    pub request_id: Uuid,
    
    /// When this decision was made
    pub timestamp: DateTime<Utc>,
    
    /// The actual decision
    pub decision: Decision,
    
    /// How confident we are in this decision (0.0 to 1.0)
    pub confidence: f64,
    
    /// Which policies were applied
    pub policies_applied: Vec<String>,
    
    /// How long it took to make this decision (in milliseconds)
    pub processing_time_ms: u64,
    
    /// Any additional information about the decision
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
}

/// The actual governance decision
/// 
/// Keep it simple - either we allow it, block it, or need human review.
/// I considered adding more granular options but decided to keep it simple for now.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Decision {
    /// Allow the request to proceed
    Allow,
    
    /// Block the request
    Block { reason: String },
    
    /// Requires human review before proceeding
    Review { reason: String },
    
    /// Allow with modifications or warnings
    AllowWithWarning { warning: String },
}

impl GovernanceRequest {
    /// Create a new governance request
    /// 
    /// This is the main entry point for creating requests. I auto-generate
    /// the ID and timestamp to make sure they're consistent.
    pub fn new(content: RequestContent, context: RequestContext) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            content,
            context,
            metadata: std::collections::HashMap::new(),
        }
    }
    
    /// Get the content type as a string
    /// 
    /// Useful for logging and metrics
    pub fn content_type(&self) -> &'static str {
        match &self.content {
            RequestContent::Text { .. } => "text",
            RequestContent::Image { .. } => "image", 
            RequestContent::Audio { .. } => "audio",
            RequestContent::Video { .. } => "video",
        }
    }
    
    /// Get the approximate size of the content
    /// 
    /// This is useful for rate limiting and resource management
    pub fn content_size(&self) -> usize {
        match &self.content {
            RequestContent::Text { content } => content.len(),
            RequestContent::Image { data, .. } => data.len(),
            RequestContent::Audio { data, .. } => data.len(),
            RequestContent::Video { data, .. } => data.len(),
        }
    }
}

impl GovernanceDecision {
    /// Create a new governance decision
    pub fn new(
        request_id: Uuid,
        decision: Decision,
        confidence: f64,
        policies_applied: Vec<String>,
        processing_time_ms: u64,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            request_id,
            timestamp: Utc::now(),
            decision,
            confidence,
            policies_applied,
            processing_time_ms,
            metadata: std::collections::HashMap::new(),
        }
    }
    
    /// Check if this decision allows the request
    pub fn is_allowed(&self) -> bool {
        matches!(self.decision, Decision::Allow | Decision::AllowWithWarning { .. })
    }
    
    /// Check if this decision blocks the request
    pub fn is_blocked(&self) -> bool {
        matches!(self.decision, Decision::Block { .. })
    }
    
    /// Check if this decision requires review
    pub fn requires_review(&self) -> bool {
        matches!(self.decision, Decision::Review { .. })
    }
}

impl Default for RequestContext {
    fn default() -> Self {
        Self {
            user_id: None,
            application: None,
            session_id: None,
            ip_address: None,
            user_agent: None,
            additional: std::collections::HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_governance_request_creation() {
        let content = RequestContent::Text {
            content: "Hello, world!".to_string(),
        };
        let context = RequestContext::default();
        
        let request = GovernanceRequest::new(content, context);
        
        assert_eq!(request.content_type(), "text");
        assert_eq!(request.content_size(), 13);
    }

    #[test]
    fn test_decision_checks() {
        let decision = GovernanceDecision::new(
            Uuid::new_v4(),
            Decision::Allow,
            0.95,
            vec!["default_policy".to_string()],
            5,
        );
        
        assert!(decision.is_allowed());
        assert!(!decision.is_blocked());
        assert!(!decision.requires_review());
    }

    #[test]
    fn test_block_decision() {
        let decision = GovernanceDecision::new(
            Uuid::new_v4(),
            Decision::Block { reason: "Test block".to_string() },
            0.89,
            vec!["security_policy".to_string()],
            3,
        );
        
        assert!(!decision.is_allowed());
        assert!(decision.is_blocked());
        assert!(!decision.requires_review());
    }
}
