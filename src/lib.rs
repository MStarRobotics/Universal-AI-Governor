//! Universal AI Governor
//!
//! A cutting-edge, hardware-backed AI governance platform designed for robust
//! enterprise deployments. This library forms the foundational core of the
//! Governor, meticulously orchestrating policy enforcement, integrating with
//! advanced hardware security modules, and maintaining an immutable audit trail.
//!
//! This project embodies the "PhD level" of engineering by tackling complex
//! challenges in AI safety, transparency, and control. It aims to introduce a
//! "humanization effect" into AI systems by ensuring they operate within defined
//! ethical and operational boundaries, thereby preventing "AI bypass" of critical
//! governance mechanisms.

#![deny(missing_docs)]
#![warn(clippy::all)]

/// Provides auditing capabilities for transparent and immutable record-keeping
/// of all AI governance decisions and events. This module is crucial for
/// forensic analysis, compliance, and establishing trust in AI systems.
pub mod audit;
/// Manages the configuration and settings for the entire AI Governor system,
/// ensuring adaptable and consistent behavior across diverse environments.
pub mod config;
/// Integrates with hardware security modules (HSMs) and Trusted Platform Modules (TPMs)
/// to provide a robust root of trust and enhanced security for AI operations.
pub mod hardware;
/// Implements the policy evaluation and enforcement engine, allowing for dynamic
/// and context-aware governance of AI interactions based on predefined rules.
pub mod policy;
/// Handles various security aspects, including authentication, authorization,
/// and secure communication channels within the AI governance framework.
pub mod security;

use thiserror::Error;

/// GovernorError represents the comprehensive error types for the Universal AI Governor.
/// Each variant provides specific context for failures, aiding in robust error handling
/// and system resilience. This detailed error reporting is vital for debugging complex
/// AI governance issues and maintaining system integrity.
#[derive(Error, Debug)]
pub enum GovernorError {
    /// Configuration error: Indicates issues with loading, parsing, or validating
    /// the system's configuration. Proper configuration is the first line of defense
    /// against misaligned AI behavior.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Policy error: Signifies problems during policy evaluation, loading, or enforcement.
    /// Failures here directly impact the system's ability to govern AI effectively.
    #[error("Policy error: {0}")]
    Policy(String),

    /// Hardware error: Relates to issues with integrated hardware security modules (HSMs)
    /// or Trusted Platform Modules (TPMs). These errors are critical as they can compromise
    /// the root of trust and the overall security posture of the AI system.
    #[error("Hardware error: {0}")]
    Hardware(String),

    /// Database error: Occurs when there are issues interacting with the underlying
    /// data storage, which is essential for audit logs, policy storage, and system state.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// IO error: Represents problems during input/output operations, such as reading
    /// files or network communication. These are fundamental operational failures.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for the Universal AI Governor, encapsulating success or a specific GovernorError.
/// This standardized result type promotes consistent error handling throughout the codebase,
/// contributing to the system's overall reliability and maintainability.
pub type Result<T> = std::result::Result<T, GovernorError>;

/// VERSION constant provides the current version of the Universal AI Governor.
/// This is crucial for tracking deployments, managing updates, and ensuring
/// traceability of the software version in audit trails.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}

