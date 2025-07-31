//! Integration tests for Universal AI Governor

use universal_ai_governor::{
    config::Config,
    policy::{Policy, PolicyManager},
    audit::{AuditLogger},
    security::SecurityManager,
};
use std::collections::HashMap;

#[tokio::test]
async fn test_policy_management_integration() {
    let mut manager = PolicyManager::new();
    
    let policy = Policy {
        id: "test-policy".to_string(),
        name: "Test Policy".to_string(),
        description: "Integration test policy".to_string(),
        rules: HashMap::new(),
        enabled: true,
    };
    
    manager.add_policy(policy);
    
    let policies = manager.get_policies();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].name, "Test Policy");
}

#[tokio::test]
async fn test_audit_logging_integration() {
    let mut logger = AuditLogger::new();
    
    logger.log_action(
        "test-user".to_string(),
        "test-action".to_string(),
        "test-resource".to_string(),
        HashMap::new(),
        Some("127.0.0.1".to_string()),
    );
    
    let logs = logger.get_logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].action, "test-action");
}

#[tokio::test]
async fn test_security_manager_integration() {
    let key = b"test-key-32-bytes-long-for-hmac!".to_vec();
    let manager = SecurityManager::new(key);
    
    let data = b"integration test data";
    let hash = manager.hash_data(data);
    assert!(!hash.is_empty());
    
    let signature = manager.create_signature(data).unwrap();
    assert!(manager.verify_signature(data, &signature));
}

#[tokio::test]
async fn test_config_integration() {
    let config = Config::default();
    
    assert_eq!(config.server.host, "127.0.0.1");
    assert_eq!(config.server.port, 8080);
    assert_eq!(config.database.url, "sqlite://governor.db");
    assert!(!config.security.enable_tpm);
    assert!(!config.security.enable_hsm);
}

#[tokio::test]
async fn test_full_system_integration() {
    // Test that all components work together
    let config = Config::default();
    let mut policy_manager = PolicyManager::new();
    let mut audit_logger = AuditLogger::new();
    let key = b"integration-test-key-32-bytes!".to_vec();
    let security_manager = SecurityManager::new(key);
    
    // Create a policy
    let policy = Policy {
        id: "integration-policy".to_string(),
        name: "Integration Policy".to_string(),
        description: "Full system integration test".to_string(),
        rules: HashMap::new(),
        enabled: true,
    };
    
    policy_manager.add_policy(policy);
    
    // Log the policy creation
    audit_logger.log_action(
        "system".to_string(),
        "policy_created".to_string(),
        "integration-policy".to_string(),
        HashMap::new(),
        None,
    );
    
    // Verify everything works
    assert_eq!(policy_manager.get_policies().len(), 1);
    assert_eq!(audit_logger.get_logs().len(), 1);
    
    let test_data = b"integration test";
    let signature = security_manager.create_signature(test_data).unwrap();
    assert!(security_manager.verify_signature(test_data, &signature));
}
