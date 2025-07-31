// AI-Driven Policy Synthesizer
// Learns from real incidents and automatically generates new governance rules

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// AI-driven policy synthesizer that learns from incidents
pub struct PolicySynthesizer {
    llm_engine: Arc<OfflineLlmEngine>,
    incident_analyzer: Arc<IncidentAnalyzer>,
    rule_generator: Arc<RuleGenerator>,
    validation_engine: Arc<ValidationEngine>,
    incident_history: RwLock<VecDeque<SecurityIncident>>,
    generated_policies: RwLock<HashMap<String, GeneratedPolicy>>,
    config: SynthesizerConfig,
}

/// Configuration for the policy synthesizer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthesizerConfig {
    pub max_incident_history: usize,
    pub llm_model_path: String,
    pub confidence_threshold: f64,
    pub auto_deploy_enabled: bool,
    pub human_approval_required: bool,
    pub learning_rate: f64,
    pub rule_retirement_days: u32,
    pub test_generation_enabled: bool,
}

/// Security incident for analysis and learning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIncident {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub incident_type: IncidentType,
    pub severity: IncidentSeverity,
    pub attack_vector: String,
    pub payload: String,
    pub detection_method: Option<String>,
    pub bypass_technique: Option<String>,
    pub affected_components: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub sanitized_logs: Vec<String>,
}

/// Types of security incidents
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentType {
    PromptInjection,
    PolicyBypass,
    AuthenticationFailure,
    PrivilegeEscalation,
    DataExfiltration,
    AdversarialInput,
    EncodingEvasion,
    TimingAttack,
    SideChannelAttack,
    NovelAttack,
}

/// Severity levels for incidents
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Generated policy rule with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedPolicy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub rego_code: String,
    pub test_cases: Vec<PolicyTestCase>,
    pub confidence_score: f64,
    pub source_incidents: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub approved_by: Option<String>,
    pub deployment_status: DeploymentStatus,
    pub effectiveness_metrics: EffectivenessMetrics,
    pub retirement_date: Option<DateTime<Utc>>,
}

/// Test cases for generated policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTestCase {
    pub name: String,
    pub input: serde_json::Value,
    pub expected_result: bool,
    pub description: String,
}

/// Deployment status of generated policies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeploymentStatus {
    Draft,
    PendingApproval,
    Approved,
    Deployed,
    Retired,
    Failed,
}

/// Effectiveness metrics for policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectivenessMetrics {
    pub incidents_prevented: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub performance_impact_ms: f64,
    pub last_triggered: Option<DateTime<Utc>>,
}

/// Offline LLM engine for policy generation
pub struct OfflineLlmEngine {
    model_path: String,
    context_window: usize,
    temperature: f32,
    max_tokens: usize,
}

/// Incident analysis engine
pub struct IncidentAnalyzer {
    pattern_database: RwLock<HashMap<String, AttackPattern>>,
    similarity_threshold: f64,
}

/// Attack pattern identified from incidents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub pattern_id: String,
    pub pattern_type: IncidentType,
    pub signature: String,
    pub variants: Vec<String>,
    pub frequency: u32,
    pub last_seen: DateTime<Utc>,
    pub mitigation_strategies: Vec<String>,
}

/// Rule generation engine
pub struct RuleGenerator {
    template_library: HashMap<IncidentType, Vec<RuleTemplate>>,
    rego_validator: RegoValidator,
}

/// Rule template for different incident types
#[derive(Debug, Clone)]
pub struct RuleTemplate {
    pub template_id: String,
    pub incident_type: IncidentType,
    pub rego_template: String,
    pub parameters: Vec<TemplateParameter>,
    pub complexity_score: u8,
}

/// Template parameter for rule generation
#[derive(Debug, Clone)]
pub struct TemplateParameter {
    pub name: String,
    pub param_type: ParameterType,
    pub description: String,
    pub default_value: Option<String>,
}

/// Parameter types for templates
#[derive(Debug, Clone)]
pub enum ParameterType {
    String,
    Regex,
    Number,
    Boolean,
    Array,
}

/// Rego code validator
pub struct RegoValidator {
    syntax_checker: RegexSyntaxChecker,
    semantic_analyzer: SemanticAnalyzer,
}

/// Validation engine for generated policies
pub struct ValidationEngine {
    test_runner: PolicyTestRunner,
    performance_analyzer: PerformanceAnalyzer,
    security_analyzer: SecurityAnalyzer,
}

impl PolicySynthesizer {
    /// Initialize the policy synthesizer
    pub async fn new(config: SynthesizerConfig) -> Result<Self, SynthesizerError> {
        let llm_engine = Arc::new(OfflineLlmEngine::new(&config.llm_model_path).await?);
        let incident_analyzer = Arc::new(IncidentAnalyzer::new(config.confidence_threshold));
        let rule_generator = Arc::new(RuleGenerator::new().await?);
        let validation_engine = Arc::new(ValidationEngine::new());

        Ok(Self {
            llm_engine,
            incident_analyzer,
            rule_generator,
            validation_engine,
            incident_history: RwLock::new(VecDeque::with_capacity(config.max_incident_history)),
            generated_policies: RwLock::new(HashMap::new()),
            config,
        })
    }

    /// Ingest a new security incident for analysis
    pub async fn ingest_incident(&self, incident: SecurityIncident) -> Result<(), SynthesizerError> {
        println!("🔍 Ingesting security incident: {} ({})", incident.id, incident.incident_type);

        // Add to incident history
        let mut history = self.incident_history.write().await;
        if history.len() >= self.config.max_incident_history {
            history.pop_front();
        }
        history.push_back(incident.clone());
        drop(history);

        // Analyze the incident
        let analysis = self.incident_analyzer.analyze_incident(&incident).await?;
        
        // Check if this represents a new attack pattern
        if analysis.is_novel_pattern {
            println!("🚨 Novel attack pattern detected: {}", analysis.pattern_signature);
            
            // Generate new policy rule
            let policy = self.generate_policy_for_incident(&incident, &analysis).await?;
            
            // Validate the generated policy
            let validation_result = self.validation_engine.validate_policy(&policy).await?;
            
            if validation_result.is_valid && validation_result.confidence_score >= self.config.confidence_threshold {
                // Store the generated policy
                let mut policies = self.generated_policies.write().await;
                policies.insert(policy.id.clone(), policy.clone());
                drop(policies);

                // Handle deployment based on configuration
                if self.config.auto_deploy_enabled && !self.config.human_approval_required {
                    self.deploy_policy(&policy.id).await?;
                } else {
                    self.request_human_approval(&policy.id).await?;
                }
            } else {
                println!("⚠️ Generated policy failed validation: {}", validation_result.failure_reason);
            }
        }

        Ok(())
    }

    /// Generate a new policy rule for an incident
    async fn generate_policy_for_incident(
        &self,
        incident: &SecurityIncident,
        analysis: &IncidentAnalysis,
    ) -> Result<GeneratedPolicy, SynthesizerError> {
        println!("🤖 Generating policy for incident type: {:?}", incident.incident_type);

        // Create context for LLM
        let context = self.build_llm_context(incident, analysis).await?;
        
        // Generate policy using LLM
        let llm_response = self.llm_engine.generate_policy(&context).await?;
        
        // Parse and validate the LLM response
        let rego_code = self.extract_rego_code(&llm_response)?;
        let test_cases = self.extract_test_cases(&llm_response)?;
        
        // Generate additional test cases
        let additional_tests = self.rule_generator.generate_test_cases(
            &rego_code,
            &incident.incident_type,
        ).await?;

        let policy = GeneratedPolicy {
            id: Uuid::new_v4().to_string(),
            name: format!("Auto-generated rule for {}", incident.incident_type),
            description: format!("Policy generated from incident {} to prevent {}", 
                               incident.id, analysis.attack_description),
            rego_code,
            test_cases: [test_cases, additional_tests].concat(),
            confidence_score: analysis.confidence_score,
            source_incidents: vec![incident.id.clone()],
            created_at: Utc::now(),
            approved_by: None,
            deployment_status: DeploymentStatus::Draft,
            effectiveness_metrics: EffectivenessMetrics {
                incidents_prevented: 0,
                false_positives: 0,
                false_negatives: 0,
                performance_impact_ms: 0.0,
                last_triggered: None,
            },
            retirement_date: None,
        };

        Ok(policy)
    }

    /// Build context for LLM policy generation
    async fn build_llm_context(
        &self,
        incident: &SecurityIncident,
        analysis: &IncidentAnalysis,
    ) -> Result<String, SynthesizerError> {
        let similar_incidents = self.find_similar_incidents(incident).await?;
        let existing_policies = self.get_related_policies(&incident.incident_type).await?;

        let context = format!(
            r#"
SECURITY INCIDENT ANALYSIS:
Incident ID: {}
Type: {:?}
Severity: {:?}
Attack Vector: {}
Payload: {}
Bypass Technique: {}

ANALYSIS RESULTS:
Pattern Signature: {}
Attack Description: {}
Root Cause: {}
Confidence Score: {:.2}

SIMILAR INCIDENTS:
{}

EXISTING POLICIES:
{}

TASK: Generate a new Rego policy rule that would prevent this type of attack.
The rule should:
1. Be specific enough to catch this attack pattern
2. Be general enough to catch variants
3. Minimize false positives
4. Include comprehensive test cases
5. Have clear comments explaining the logic

FORMAT:
```rego
# Policy Name: [descriptive name]
# Description: [what this policy prevents]
# Generated: {}

package governor.policies.auto_generated

[your rego rule here]
```

TEST CASES:
```json
[
  {{
    "name": "should_block_attack",
    "input": {{"payload": "example malicious input"}},
    "expected": false,
    "description": "Should block the original attack"
  }},
  {{
    "name": "should_allow_benign",
    "input": {{"payload": "example benign input"}},
    "expected": true,
    "description": "Should allow legitimate requests"
  }}
]
```
"#,
            incident.id,
            incident.incident_type,
            incident.severity,
            incident.attack_vector,
            incident.payload,
            incident.bypass_technique.as_deref().unwrap_or("None"),
            analysis.pattern_signature,
            analysis.attack_description,
            analysis.root_cause,
            analysis.confidence_score,
            self.format_similar_incidents(&similar_incidents),
            self.format_existing_policies(&existing_policies),
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        );

        Ok(context)
    }

    /// Find similar incidents for context
    async fn find_similar_incidents(&self, incident: &SecurityIncident) -> Result<Vec<SecurityIncident>, SynthesizerError> {
        let history = self.incident_history.read().await;
        let similar: Vec<SecurityIncident> = history
            .iter()
            .filter(|i| {
                i.incident_type == incident.incident_type ||
                self.calculate_similarity(&i.payload, &incident.payload) > 0.7
            })
            .take(3)
            .cloned()
            .collect();
        Ok(similar)
    }

    /// Get related existing policies
    async fn get_related_policies(&self, incident_type: &IncidentType) -> Result<Vec<GeneratedPolicy>, SynthesizerError> {
        let policies = self.generated_policies.read().await;
        let related: Vec<GeneratedPolicy> = policies
            .values()
            .filter(|p| {
                p.source_incidents.iter().any(|id| {
                    // This would check if the source incident has the same type
                    // For now, we'll use a simple heuristic
                    p.name.contains(&format!("{:?}", incident_type))
                })
            })
            .take(2)
            .cloned()
            .collect();
        Ok(related)
    }

    /// Calculate similarity between two payloads
    fn calculate_similarity(&self, payload1: &str, payload2: &str) -> f64 {
        // Simple Jaccard similarity for demonstration
        let words1: std::collections::HashSet<&str> = payload1.split_whitespace().collect();
        let words2: std::collections::HashSet<&str> = payload2.split_whitespace().collect();
        
        let intersection = words1.intersection(&words2).count();
        let union = words1.union(&words2).count();
        
        if union == 0 {
            0.0
        } else {
            intersection as f64 / union as f64
        }
    }

    /// Format similar incidents for LLM context
    fn format_similar_incidents(&self, incidents: &[SecurityIncident]) -> String {
        if incidents.is_empty() {
            return "No similar incidents found.".to_string();
        }

        incidents
            .iter()
            .map(|i| format!("- {} ({}): {}", i.id, i.incident_type, i.attack_vector))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Format existing policies for LLM context
    fn format_existing_policies(&self, policies: &[GeneratedPolicy]) -> String {
        if policies.is_empty() {
            return "No related policies found.".to_string();
        }

        policies
            .iter()
            .map(|p| format!("- {}: {}", p.name, p.description))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Extract Rego code from LLM response
    fn extract_rego_code(&self, response: &str) -> Result<String, SynthesizerError> {
        // Extract code between ```rego and ```
        if let Some(start) = response.find("```rego") {
            if let Some(end) = response[start..].find("```") {
                let code_start = start + 7; // Length of "```rego"
                let code_end = start + end;
                return Ok(response[code_start..code_end].trim().to_string());
            }
        }
        
        Err(SynthesizerError::InvalidLlmResponse("No Rego code found in response".to_string()))
    }

    /// Extract test cases from LLM response
    fn extract_test_cases(&self, response: &str) -> Result<Vec<PolicyTestCase>, SynthesizerError> {
        // Extract JSON between ```json and ```
        if let Some(start) = response.find("```json") {
            if let Some(end) = response[start..].find("```") {
                let json_start = start + 7; // Length of "```json"
                let json_end = start + end;
                let json_str = response[json_start..json_end].trim();
                
                let test_cases: Vec<serde_json::Value> = serde_json::from_str(json_str)
                    .map_err(|e| SynthesizerError::InvalidLlmResponse(format!("Invalid JSON: {}", e)))?;
                
                let mut parsed_cases = Vec::new();
                for case in test_cases {
                    let test_case = PolicyTestCase {
                        name: case["name"].as_str().unwrap_or("unnamed_test").to_string(),
                        input: case["input"].clone(),
                        expected_result: case["expected"].as_bool().unwrap_or(false),
                        description: case["description"].as_str().unwrap_or("").to_string(),
                    };
                    parsed_cases.push(test_case);
                }
                
                return Ok(parsed_cases);
            }
        }
        
        Ok(Vec::new()) // Return empty if no test cases found
    }

    /// Request human approval for a generated policy
    async fn request_human_approval(&self, policy_id: &str) -> Result<(), SynthesizerError> {
        let mut policies = self.generated_policies.write().await;
        if let Some(policy) = policies.get_mut(policy_id) {
            policy.deployment_status = DeploymentStatus::PendingApproval;
            println!("📋 Policy {} is pending human approval", policy_id);
            
            // In a real implementation, this would:
            // 1. Send notification to security team
            // 2. Create approval workflow ticket
            // 3. Display in management dashboard
        }
        Ok(())
    }

    /// Deploy a policy to production
    pub async fn deploy_policy(&self, policy_id: &str) -> Result<(), SynthesizerError> {
        let mut policies = self.generated_policies.write().await;
        if let Some(policy) = policies.get_mut(policy_id) {
            // Validate policy before deployment
            let validation = self.validation_engine.validate_policy(policy).await?;
            if !validation.is_valid {
                return Err(SynthesizerError::ValidationFailed(validation.failure_reason));
            }

            // Deploy to policy engine
            // In a real implementation, this would integrate with the actual policy engine
            policy.deployment_status = DeploymentStatus::Deployed;
            
            println!("🚀 Policy {} deployed successfully", policy_id);
            
            // Add to integration tests
            self.add_to_integration_tests(policy).await?;
        }
        Ok(())
    }

    /// Add generated policy to integration test suite
    async fn add_to_integration_tests(&self, policy: &GeneratedPolicy) -> Result<(), SynthesizerError> {
        // Generate integration test file
        let test_code = format!(
            r#"
// Auto-generated integration test for policy: {}
// Generated: {}

#[cfg(test)]
mod test_{} {{
    use super::*;

    #[tokio::test]
    async fn test_generated_policy_{}() {{
        let policy_engine = PolicyEngine::new().await.unwrap();
        
        // Load the generated policy
        policy_engine.load_policy(r#"{}"#).await.unwrap();
        
        // Run test cases
{}
    }}
}}
"#,
            policy.name,
            policy.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
            policy.id.replace("-", "_"),
            policy.id.replace("-", "_"),
            policy.rego_code,
            self.generate_test_code(&policy.test_cases)
        );

        // Write to test file
        let test_file_path = format!("tests/generated/policy_{}.rs", policy.id);
        tokio::fs::write(&test_file_path, test_code).await
            .map_err(|e| SynthesizerError::FileError(format!("Failed to write test file: {}", e)))?;

        println!("📝 Integration test generated: {}", test_file_path);
        Ok(())
    }

    /// Generate test code for policy test cases
    fn generate_test_code(&self, test_cases: &[PolicyTestCase]) -> String {
        test_cases
            .iter()
            .map(|case| {
                format!(
                    r#"
        // Test: {}
        let input = serde_json::json!({});
        let result = policy_engine.evaluate(&input).await.unwrap();
        assert_eq!(result.allowed, {}, "{}");
"#,
                    case.name,
                    serde_json::to_string_pretty(&case.input).unwrap_or_default(),
                    case.expected_result,
                    case.description
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Approve a pending policy
    pub async fn approve_policy(&self, policy_id: &str, approver: &str) -> Result<(), SynthesizerError> {
        let mut policies = self.generated_policies.write().await;
        if let Some(policy) = policies.get_mut(policy_id) {
            if policy.deployment_status == DeploymentStatus::PendingApproval {
                policy.approved_by = Some(approver.to_string());
                policy.deployment_status = DeploymentStatus::Approved;
                
                println!("✅ Policy {} approved by {}", policy_id, approver);
                
                // Auto-deploy if configured
                if self.config.auto_deploy_enabled {
                    drop(policies); // Release lock before calling deploy_policy
                    self.deploy_policy(policy_id).await?;
                }
            }
        }
        Ok(())
    }

    /// Get all generated policies
    pub async fn get_generated_policies(&self) -> Vec<GeneratedPolicy> {
        let policies = self.generated_policies.read().await;
        policies.values().cloned().collect()
    }

    /// Get policy effectiveness metrics
    pub async fn get_policy_metrics(&self, policy_id: &str) -> Option<EffectivenessMetrics> {
        let policies = self.generated_policies.read().await;
        policies.get(policy_id).map(|p| p.effectiveness_metrics.clone())
    }

    /// Update policy effectiveness based on real-world performance
    pub async fn update_policy_effectiveness(
        &self,
        policy_id: &str,
        prevented_incident: bool,
        false_positive: bool,
        performance_impact: f64,
    ) -> Result<(), SynthesizerError> {
        let mut policies = self.generated_policies.write().await;
        if let Some(policy) = policies.get_mut(policy_id) {
            if prevented_incident {
                policy.effectiveness_metrics.incidents_prevented += 1;
                policy.effectiveness_metrics.last_triggered = Some(Utc::now());
            }
            if false_positive {
                policy.effectiveness_metrics.false_positives += 1;
            }
            policy.effectiveness_metrics.performance_impact_ms = performance_impact;
        }
        Ok(())
    }

    /// Retire obsolete policies
    pub async fn retire_obsolete_policies(&self) -> Result<Vec<String>, SynthesizerError> {
        let mut retired_policies = Vec::new();
        let mut policies = self.generated_policies.write().await;
        
        let cutoff_date = Utc::now() - chrono::Duration::days(self.config.rule_retirement_days as i64);
        
        for (policy_id, policy) in policies.iter_mut() {
            // Retire policies that haven't been triggered recently and have high false positive rates
            let should_retire = policy.created_at < cutoff_date &&
                policy.effectiveness_metrics.incidents_prevented == 0 &&
                policy.effectiveness_metrics.false_positives > 10;
            
            if should_retire {
                policy.deployment_status = DeploymentStatus::Retired;
                policy.retirement_date = Some(Utc::now());
                retired_policies.push(policy_id.clone());
                println!("🗑️ Retired obsolete policy: {}", policy.name);
            }
        }
        
        Ok(retired_policies)
    }
}

/// Incident analysis result
#[derive(Debug)]
pub struct IncidentAnalysis {
    pub is_novel_pattern: bool,
    pub pattern_signature: String,
    pub attack_description: String,
    pub root_cause: String,
    pub confidence_score: f64,
    pub recommended_actions: Vec<String>,
}

/// Policy validation result
#[derive(Debug)]
pub struct PolicyValidationResult {
    pub is_valid: bool,
    pub confidence_score: f64,
    pub failure_reason: String,
    pub performance_estimate: f64,
    pub security_score: f64,
}

/// Policy synthesizer errors
#[derive(Debug, thiserror::Error)]
pub enum SynthesizerError {
    #[error("LLM engine error: {0}")]
    LlmError(String),
    
    #[error("Invalid LLM response: {0}")]
    InvalidLlmResponse(String),
    
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
    
    #[error("File error: {0}")]
    FileError(String),
    
    #[error("Policy not found: {0}")]
    PolicyNotFound(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

impl Default for SynthesizerConfig {
    fn default() -> Self {
        Self {
            max_incident_history: 1000,
            llm_model_path: "./models/policy_generator.gguf".to_string(),
            confidence_threshold: 0.8,
            auto_deploy_enabled: false,
            human_approval_required: true,
            learning_rate: 0.1,
            rule_retirement_days: 90,
            test_generation_enabled: true,
        }
    }
}

impl Default for EffectivenessMetrics {
    fn default() -> Self {
        Self {
            incidents_prevented: 0,
            false_positives: 0,
            false_negatives: 0,
            performance_impact_ms: 0.0,
            last_triggered: None,
        }
    }
}
