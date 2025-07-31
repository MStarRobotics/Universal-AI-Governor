// Copyright (c) 2025 Sourav Rajak
// SPDX-License-Identifier: MIT

//! Configuration management for Universal AI Governor
//!
//! This module handles loading, validation, and management of configuration
//! for all components of the Universal AI Governor system.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

/// Main configuration structure for Universal AI Governor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernorConfig {
    /// Server configuration
    pub server: ServerConfig,
    
    /// Hardware security configuration
    pub hardware: HardwareConfig,
    
    /// AI policy synthesis configuration
    pub ai_synthesis: AiSynthesisConfig,
    
    /// Database configuration
    pub database: DatabaseConfig,
    
    /// Logging configuration
    pub logging: LoggingConfig,
    
    /// Security configuration
    pub security: SecurityConfig,
    
    /// Compliance configuration
    pub compliance: ComplianceConfig,
    
    /// Legacy fields for backward compatibility
    pub offline_mode: bool,
    pub challenge_expiry_seconds: u64,
    pub max_failed_attempts: u32,
    pub lockout_duration_seconds: u64,
    pub tmp_enabled: bool,
    pub post_quantum_enabled: bool,
    pub audit_level: AuditLevel,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
    pub max_connections: usize,
    pub request_timeout_seconds: u64,
    pub keep_alive_seconds: u64,
    pub tls_enabled: bool,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
}

/// Hardware security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareConfig {
    pub tpm_enabled: bool,
    pub tpm_device_path: String,
    pub hsm_enabled: bool,
    pub hsm_library_path: Option<String>,
    pub secure_enclave_enabled: bool,
    pub pcr_binding_enabled: bool,
    pub hardware_attestation_required: bool,
    pub fallback_to_software: bool,
}

/// AI policy synthesis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiSynthesisConfig {
    pub enabled: bool,
    pub llm_model_path: String,
    pub confidence_threshold: f64,
    pub auto_deploy_enabled: bool,
    pub human_approval_required: bool,
    pub max_incident_history: usize,
    pub learning_rate: f64,
    pub rule_retirement_days: u32,
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub connection_timeout_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub redis_url: Option<String>,
    pub redis_cluster_mode: bool,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub file_path: Option<String>,
    pub max_file_size_mb: u64,
    pub max_files: u32,
    pub structured_logging: bool,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub jwt_secret: String,
    pub jwt_expiry_hours: u64,
    pub password_min_length: usize,
    pub password_require_special: bool,
    pub session_timeout_minutes: u64,
    pub max_login_attempts: u32,
    pub lockout_duration_minutes: u64,
    pub rate_limit_requests_per_minute: u32,
}

/// Compliance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    pub gdpr_enabled: bool,
    pub hipaa_enabled: bool,
    pub soc2_enabled: bool,
    pub data_retention_days: u32,
    pub audit_log_retention_days: u32,
    pub encryption_at_rest: bool,
    pub encryption_in_transit: bool,
}

/// Audit levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuditLevel {
    /// Minimal auditing
    Minimal,
    /// Standard auditing
    Standard,
    /// Comprehensive auditing
    Comprehensive,
    /// Full forensic auditing
    Forensic,
}

impl GovernorConfig {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| ConfigError::FileRead(e.to_string()))?;
        
        let config: Self = toml::from_str(&content)
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;
        
        config.validate()?;
        Ok(config)
    }

    /// Save configuration to a TOML file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::SerializeError(e.to_string()))?;
        
        std::fs::write(path.as_ref(), content)
            .map_err(|e| ConfigError::FileWrite(e.to_string()))?;
        
        Ok(())
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate server configuration
        if self.server.port == 0 {
            return Err(ConfigError::ValidationError("Server port cannot be 0".to_string()));
        }
        
        if self.server.workers == 0 {
            return Err(ConfigError::ValidationError("Worker count cannot be 0".to_string()));
        }

        // Validate hardware configuration
        if self.hardware.tpm_enabled && self.hardware.tmp_device_path.is_empty() {
            return Err(ConfigError::ValidationError("TPM device path required when TPM is enabled".to_string()));
        }

        // Validate AI synthesis configuration
        if self.ai_synthesis.enabled {
            if self.ai_synthesis.llm_model_path.is_empty() {
                return Err(ConfigError::ValidationError("LLM model path required when AI synthesis is enabled".to_string()));
            }
            
            if !(0.0..=1.0).contains(&self.ai_synthesis.confidence_threshold) {
                return Err(ConfigError::ValidationError("Confidence threshold must be between 0.0 and 1.0".to_string()));
            }
        }

        // Validate database configuration
        if self.database.url.is_empty() {
            return Err(ConfigError::ValidationError("Database URL cannot be empty".to_string()));
        }

        // Validate security configuration
        if self.security.jwt_secret.len() < 32 {
            return Err(ConfigError::ValidationError("JWT secret must be at least 32 characters".to_string()));
        }

        Ok(())
    }

    /// Get the challenge expiry duration
    pub fn challenge_expiry_duration(&self) -> Duration {
        Duration::from_secs(self.challenge_expiry_seconds)
    }

    /// Get the lockout duration
    pub fn lockout_duration(&self) -> Duration {
        Duration::from_secs(self.lockout_duration_seconds)
    }

    /// Check if hardware security is enabled
    pub fn is_hardware_enabled(&self) -> bool {
        self.hardware.tpm_enabled || self.hardware.hsm_enabled || self.hardware.secure_enclave_enabled
    }

    /// Check if compliance features are enabled
    pub fn is_compliance_enabled(&self) -> bool {
        self.compliance.gdpr_enabled || self.compliance.hipaa_enabled || self.compliance.soc2_enabled
    }
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            hardware: HardwareConfig::default(),
            ai_synthesis: AiSynthesisConfig::default(),
            database: DatabaseConfig::default(),
            logging: LoggingConfig::default(),
            security: SecurityConfig::default(),
            compliance: ComplianceConfig::default(),
            
            // Legacy fields
            offline_mode: false,
            challenge_expiry_seconds: 300,
            max_failed_attempts: 3,
            lockout_duration_seconds: 900,
            tpm_enabled: false,
            post_quantum_enabled: false,
            audit_level: AuditLevel::Standard,
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            workers: num_cpus::get(),
            max_connections: 1000,
            request_timeout_seconds: 30,
            keep_alive_seconds: 60,
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

impl Default for HardwareConfig {
    fn default() -> Self {
        Self {
            tpm_enabled: false,
            tpm_device_path: "/dev/tpm0".to_string(),
            hsm_enabled: false,
            hsm_library_path: None,
            secure_enclave_enabled: cfg!(target_os = "macos"),
            pcr_binding_enabled: true,
            hardware_attestation_required: false,
            fallback_to_software: true,
        }
    }
}

impl Default for AiSynthesisConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            llm_model_path: "./models/policy_generator.gguf".to_string(),
            confidence_threshold: 0.8,
            auto_deploy_enabled: false,
            human_approval_required: true,
            max_incident_history: 1000,
            learning_rate: 0.1,
            rule_retirement_days: 90,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "sqlite://./data/governor.db".to_string(),
            max_connections: 10,
            connection_timeout_seconds: 30,
            idle_timeout_seconds: 600,
            redis_url: None,
            redis_cluster_mode: false,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "json".to_string(),
            file_path: Some("./logs/governor.log".to_string()),
            max_file_size_mb: 100,
            max_files: 10,
            structured_logging: true,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "change-this-in-production-to-a-secure-random-string".to_string(),
            jwt_expiry_hours: 24,
            password_min_length: 12,
            password_require_special: true,
            session_timeout_minutes: 480, // 8 hours
            max_login_attempts: 5,
            lockout_duration_minutes: 15,
            rate_limit_requests_per_minute: 100,
        }
    }
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        Self {
            gdpr_enabled: false,
            hipaa_enabled: false,
            soc2_enabled: false,
            data_retention_days: 365,
            audit_log_retention_days: 2555, // 7 years
            encryption_at_rest: true,
            encryption_in_transit: true,
        }
    }
}

/// Configuration errors
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    FileRead(String),
    
    #[error("Failed to write config file: {0}")]
    FileWrite(String),
    
    #[error("Failed to parse config: {0}")]
    ParseError(String),
    
    #[error("Failed to serialize config: {0}")]
    SerializeError(String),
    
    #[error("Configuration validation error: {0}")]
    ValidationError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config_validation() {
        let config = GovernorConfig::default();
        
        // Default config should not validate due to weak JWT secret
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_serialization() {
        let mut config = GovernorConfig::default();
        config.security.jwt_secret = "a-very-secure-jwt-secret-that-is-long-enough-for-validation".to_string();
        
        let temp_file = NamedTempFile::new().unwrap();
        config.to_file(temp_file.path()).unwrap();
        
        let loaded_config = GovernorConfig::from_file(temp_file.path()).unwrap();
        assert_eq!(config.server.port, loaded_config.server.port);
        assert_eq!(config.security.jwt_secret, loaded_config.security.jwt_secret);
    }

    #[test]
    fn test_hardware_enabled_check() {
        let mut config = GovernorConfig::default();
        assert!(!config.is_hardware_enabled());
        
        config.hardware.tpm_enabled = true;
        assert!(config.is_hardware_enabled());
    }

    #[test]
    fn test_compliance_enabled_check() {
        let mut config = GovernorConfig::default();
        assert!(!config.is_compliance_enabled());
        
        config.compliance.gdpr_enabled = true;
        assert!(config.is_compliance_enabled());
    }

    #[test]
    fn test_duration_helpers() {
        let config = GovernorConfig::default();
        
        assert_eq!(config.challenge_expiry_duration(), Duration::from_secs(300));
        assert_eq!(config.lockout_duration(), Duration::from_secs(900));
    }
}
