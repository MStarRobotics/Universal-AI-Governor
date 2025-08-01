//! Configuration management for Universal AI Governor
//!
//! This module defines the data structures and logic for managing the configuration
//! of the Universal AI Governor. A robust and transparent configuration system is
//! essential for achieving the "humanization effect" in AI governance, as it allows
//! human operators to understand and control the system's behavior. By externalizing
//! and clearly defining operational parameters, it also facilitates "AI bypass"
//! of hardcoded behaviors, enabling dynamic adaptation and fine-tuning of AI governance
//! policies without requiring code changes.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Main configuration structure for the Universal AI Governor.
/// This comprehensive structure encapsulates all the necessary settings
/// for the server, database, and security components, providing a single,
/// coherent source of truth for the system's operational parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server configuration: Defines how the Governor's API server operates,
    /// including network binding and port settings.
    pub server: ServerConfig,
    /// Database configuration: Specifies connection details and parameters
    /// for the underlying data storage, crucial for audit logs and policy persistence.
    pub database: DatabaseConfig,
    /// Security configuration: Controls the activation of hardware-backed
    /// security features like TPM and HSM integration, which are vital for
    /// establishing a root of trust and enhancing the overall security posture.
    pub security: SecurityConfig,
}

/// Server configuration: Details for the HTTP server component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server host: The network interface or IP address the server will bind to.
    pub host: String,
    /// Server port: The port number on which the server will listen for incoming requests.
    pub port: u16,
}

/// Database configuration: Details for connecting to the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database URL: The connection string for the database (e.g., `sqlite://governor.db`).
    pub url: String,
    /// Maximum connections: The maximum number of concurrent connections to the database,
    /// optimizing resource utilization and preventing overload.
    pub max_connections: u32,
}

/// Security configuration: Settings for hardware-backed security features.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable TPM integration: A boolean flag to activate Trusted Platform Module (TPM)
    /// functionalities for enhanced platform integrity and cryptographic operations.
    pub enable_tpm: bool,
    /// Enable HSM integration: A boolean flag to activate Hardware Security Module (HSM)
    /// functionalities for secure key storage and cryptographic acceleration.
    pub enable_hsm: bool,
}

impl Default for Config {
    /// Provides a default configuration for the Universal AI Governor.
    /// These defaults ensure that the system can be run out-of-the-box,
    /// providing a baseline for development and testing. In a production
    /// environment, these values would typically be overridden by external
    /// configuration files or environment variables.
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
            },
            database: DatabaseConfig {
                url: "sqlite://governor.db".to_string(),
                max_connections: 10,
            },
            security: SecurityConfig {
                enable_tpm: false,
                enable_hsm: false,
            },
        }
    }
}

impl Config {
    /// Loads configuration from a specified file path.
    /// This function is critical for externalizing configuration, allowing for
    /// flexible deployment and dynamic adjustment of the Governor's behavior.
    /// It supports the "AI bypass" of hardcoded settings, enabling operators
    /// to adapt the system to evolving requirements without recompilation.
    pub fn from_file<P: AsRef<Path>>(path: P) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config =
            toml::from_str(&content).map_err(|e| crate::GovernorError::Config(e.to_string()))?;
        Ok(config)
    }
}
