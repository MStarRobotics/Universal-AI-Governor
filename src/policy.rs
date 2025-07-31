//! Policy management for Universal AI Governor

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// AI Governance Policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy ID
    pub id: String,
    /// Policy name
    pub name: String,
    /// Policy description
    pub description: String,
    /// Policy rules
    pub rules: HashMap<String, serde_json::Value>,
    /// Whether the policy is enabled
    pub enabled: bool,
}

/// Policy manager
#[derive(Debug)]
pub struct PolicyManager {
    policies: Vec<Policy>,
}

impl PolicyManager {
    /// Create a new policy manager
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }
    
    /// Add a policy
    pub fn add_policy(&mut self, policy: Policy) {
        self.policies.push(policy);
    }
    
    /// Get all policies
    pub fn get_policies(&self) -> &[Policy] {
        &self.policies
    }
    
    /// Get a policy by ID
    pub fn get_policy(&self, id: &str) -> Option<&Policy> {
        self.policies.iter().find(|p| p.id == id)
    }
}

impl Default for PolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_manager() {
        let mut manager = PolicyManager::new();
        
        let policy = Policy {
            id: "test".to_string(),
            name: "Test Policy".to_string(),
            description: "A test policy".to_string(),
            rules: HashMap::new(),
            enabled: true,
        };
        
        manager.add_policy(policy);
        assert_eq!(manager.get_policies().len(), 1);
        assert!(manager.get_policy("test").is_some());
    }
}
