//! Universal AI Governor
//! 
//! Hardware-backed AI governance platform for enterprise deployments.
//! 
//! This library provides the core functionality for the Universal AI Governor,
//! including policy management, hardware security integration, and audit logging.

#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod config;
pub mod policy;
pub mod audit;
pub mod security;
pub mod hardware;

use thiserror::Error;

/// Main error type for the Universal AI Governor
#[derive(Error, Debug)]
pub enum GovernorError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),
    
    /// Policy error
    #[error("Policy error: {0}")]
    Policy(String),
    
    /// Hardware error
    #[error("Hardware error: {0}")]
    Hardware(String),
    
    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for the Universal AI Governor
pub type Result<T> = std::result::Result<T, GovernorError>;

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
