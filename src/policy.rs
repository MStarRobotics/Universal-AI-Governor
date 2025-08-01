//! Policy management for Universal AI Governor
//!
//! This module is dedicated to the robust management and enforcement of AI governance policies
//! within the Universal AI Governor. It is a central pillar for achieving the "humanization effect"
//! by translating abstract ethical and operational guidelines into concrete, executable rules
//! that govern AI behavior. By providing a transparent and auditable policy framework, it enables
//! "AI bypass" of unpredictable or undesirable outcomes, ensuring that AI systems operate within
//! predefined boundaries and align with human values.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents an AI Governance Policy.
/// A policy is a fundamental building block of the governance framework, defining
/// specific rules and conditions that AI interactions must adhere to. Each policy
/// is uniquely identified and can be enabled or disabled dynamically, allowing for
/// agile adaptation to evolving governance requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// A unique identifier for the policy, ensuring its distinct recognition within the system.
    pub id: String,
    /// A human-readable name for the policy, facilitating easy identification and understanding.
    pub name: String,
    /// A detailed description of the policy's purpose and scope, enhancing transparency.
    pub description: String,
    /// A collection of rules that define the policy's logic. These rules are typically
    /// expressed in a structured format (e.g., JSON, Rego) and are evaluated by the
    /// policy engine to make governance decisions.
    pub rules: HashMap<String, serde_json::Value>,
    /// A boolean flag indicating whether the policy is currently active and enforced.
    /// This allows for dynamic activation or deactivation of governance rules.
    pub enabled: bool,
}

/// Manages the collection and lifecycle of AI governance policies.
/// The `PolicyManager` provides functionalities for adding, retrieving, and managing
/// policies, acting as the central repository for all governance rules. Its design
/// supports the dynamic nature of AI governance, allowing for flexible policy updates
/// and consistent application across the system.
#[derive(Debug)]
pub struct PolicyManager {
    policies: Vec<Policy>,
}

impl PolicyManager {
    /// Creates a new, empty instance of the `PolicyManager`.
    /// This initializes the policy store, ready to accept and manage governance rules.
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Adds a new policy to the manager's collection.
    /// This function allows for the dynamic introduction of new governance rules
    /// into the system, enabling continuous adaptation to evolving requirements.
    pub fn add_policy(&mut self, policy: Policy) {
        self.policies.push(policy);
    }

    /// Retrieves all currently managed policies.
    /// This provides a comprehensive overview of the active governance rules,
    /// essential for auditing, reporting, and ensuring transparency in AI operations.
    pub fn get_policies(&self) -> &[Policy] {
        &self.policies
    }

    /// Retrieves a specific policy by its unique identifier.
    /// This function allows for targeted access to individual governance rules,
    /// facilitating detailed inspection and management of specific policies.
    pub fn get_policy(&self, id: &str) -> Option<&Policy> {
        self.policies.iter().find(|p| p.id == id)
    }
}

impl Default for PolicyManager {
    /// Provides a default instance of `PolicyManager`.
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
        assert!(manager.get_policy("non_existent").is_none());

        let retrieved_policy = manager.get_policy("test").unwrap();
        assert_eq!(retrieved_policy.name, "Test Policy");
    }
}
