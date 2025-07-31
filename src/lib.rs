//! Universal AI Governor
//! 
//! A hardware-backed AI governance platform for enterprise deployments.
//! 
//! This library provides comprehensive AI governance capabilities including:
//! - Hardware-backed security (TPM, HSM, Secure Enclave)
//! - Self-evolving policy synthesis using offline LLMs
//! - Multi-modal content governance (text, image, audio, video)
//! - Regulatory compliance automation (GDPR, HIPAA, SOC2)
//! 
//! # Quick Start
//! 
//! ```rust,no_run
//! use universal_ai_governor::{GovernorConfig, GovernorCore};
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = GovernorConfig::default();
//!     let governor = GovernorCore::new(config).await?;
//!     governor.run().await?;
//!     Ok(())
//! }
//! ```

pub mod core;
pub mod security;
pub mod hardware;
pub mod ai;
pub mod multimedia;
pub mod compliance;
pub mod api;
pub mod storage;
pub mod config;
pub mod utils;

// Re-export commonly used types
pub use core::{GovernorCore, GovernanceRequest, GovernanceDecision};
pub use config::GovernorConfig;
pub use security::{AuthenticationError, AuthorizationError};

/// Result type used throughout the library
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for the Universal AI Governor
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),
    
    #[error("Security error: {0}")]
    Security(#[from] security::SecurityError),
    
    #[error("Hardware error: {0}")]
    Hardware(#[from] hardware::HardwareError),
    
    #[error("AI processing error: {0}")]
    AI(#[from] ai::AIError),
    
    #[error("Multimedia processing error: {0}")]
    Multimedia(#[from] multimedia::MultimediaError),
    
    #[error("Storage error: {0}")]
    Storage(#[from] storage::StorageError),
    
    #[error("API error: {0}")]
    API(#[from] api::APIError),
    
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Other error: {0}")]
    Other(String),
}

// Some utility functions that I find myself using everywhere

/// Initialize the governor with default settings
/// 
/// This is a convenience function for simple use cases. For production
/// deployments, you should use a proper configuration file.
pub async fn init_default() -> Result<GovernorCore> {
    let config = GovernorConfig::default();
    GovernorCore::new(config).await
}

/// Validate a governance policy
/// 
/// This is a standalone function for validating policies without
/// initializing the full governor system.
pub fn validate_policy(policy: &str) -> Result<()> {
    // TODO: Implement policy validation logic
    // For now, just check if it's not empty
    if policy.trim().is_empty() {
        return Err(Error::Other("Policy cannot be empty".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_policy_rejects_empty() {
        assert!(validate_policy("").is_err());
        assert!(validate_policy("   ").is_err());
    }

    #[test]
    fn test_validate_policy_accepts_non_empty() {
        assert!(validate_policy("package test; allow = true").is_ok());
    }
}
