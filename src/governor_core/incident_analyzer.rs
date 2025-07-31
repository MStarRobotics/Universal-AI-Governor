// Incident Analyzer - Pattern Recognition and Root Cause Analysis
// Analyzes security incidents to identify novel patterns and recommend policies

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use regex::Regex;
use chrono::{DateTime, Utc, Duration};

use crate::governor_core::policy_synthesizer::{
    SecurityIncident, IncidentType, IncidentSeverity, AttackPattern
};

/// Incident analyzer for pattern recognition
pub struct IncidentAnalyzer {
    pattern_database: RwLock<HashMap<String, AttackPattern>>,
    similarity_threshold: f64,
    pattern_extractors: Vec<Box<dyn PatternExtractor + Send + Sync>>,
    ml_classifier: Option<Arc<MlClassifier>>,
    config: AnalyzerConfig,
}

/// Configuration for incident analyzer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerConfig {
    pub similarity_threshold: f64,
    pub min_pattern_frequency: u32,
    pub pattern_decay_days: u32,
    pub ml_classification_enabled: bool,
    pub real_time_analysis: bool,
    pub pattern_clustering_enabled: bool,
}

/// Analysis result for a security incident
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentAnalysis {
    pub incident_id: String,
    pub is_novel_pattern: bool,
    pub pattern_signature: String,
    pub attack_description: String,
    pub root_cause: String,
    pub confidence_score: f64,
    pub severity_assessment: IncidentSeverity,
    pub similar_incidents: Vec<String>,
    pub recommended_actions: Vec<String>,
    pub attack_vectors: Vec<String>,
    pub indicators_of_compromise: Vec<String>,
    pub pattern_evolution: Option<PatternEvolution>,
}

/// Pattern evolution tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternEvolution {
    pub base_pattern_id: String,
    pub evolution_type: EvolutionType,
    pub new_techniques: Vec<String>,
    pub evasion_methods: Vec<String>,
    pub complexity_increase: f64,
}

/// Types of pattern evolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvolutionType {
    Mutation,      // Small changes to existing pattern
    Combination,   // Combining multiple patterns
    Sophistication, // Increased complexity
    Evasion,       // New evasion techniques
    Novel,         // Completely new pattern
}

/// Pattern extractor trait for different attack types
pub trait PatternExtractor {
    fn extract_patterns(&self, incident: &SecurityIncident) -> Vec<ExtractedPattern>;
    fn get_pattern_type(&self) -> IncidentType;
    fn get_confidence(&self, pattern: &str) -> f64;
}

/// Extracted pattern from incident
#[derive(Debug, Clone)]
pub struct ExtractedPattern {
    pub pattern_type: IncidentType,
    pub signature: String,
    pub features: HashMap<String, String>,
    pub confidence: f64,
    pub indicators: Vec<String>,
}

/// ML classifier for incident categorization
pub struct MlClassifier {
    model_path: String,
    feature_extractors: Vec<Box<dyn FeatureExtractor + Send + Sync>>,
    classification_cache: RwLock<HashMap<String, ClassificationResult>>,
}

/// Feature extractor for ML classification
pub trait FeatureExtractor {
    fn extract_features(&self, incident: &SecurityIncident) -> Vec<f64>;
    fn get_feature_names(&self) -> Vec<String>;
}

/// ML classification result
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    pub predicted_type: IncidentType,
    pub confidence: f64,
    pub feature_importance: HashMap<String, f64>,
    pub anomaly_score: f64,
}

impl IncidentAnalyzer {
    /// Create new incident analyzer
    pub fn new(similarity_threshold: f64) -> Self {
        let config = AnalyzerConfig::default();
        let pattern_extractors = Self::create_pattern_extractors();
        
        Self {
            pattern_database: RwLock::new(HashMap::new()),
            similarity_threshold,
            pattern_extractors,
            ml_classifier: None,
            config,
        }
    }

    /// Create pattern extractors for different attack types
    fn create_pattern_extractors() -> Vec<Box<dyn PatternExtractor + Send + Sync>> {
        vec![
            Box::new(PromptInjectionExtractor::new()),
            Box::new(SqlInjectionExtractor::new()),
            Box::new(XssExtractor::new()),
            Box::new(CommandInjectionExtractor::new()),
            Box::new(EncodingEvasionExtractor::new()),
            Box::new(PolicyBypassExtractor::new()),
        ]
    }

    /// Analyze a security incident
    pub async fn analyze_incident(&self, incident: &SecurityIncident) -> Result<IncidentAnalysis, AnalyzerError> {
        println!("🔍 Analyzing incident: {} ({})", incident.id, incident.incident_type);

        // Extract patterns from the incident
        let extracted_patterns = self.extract_all_patterns(incident).await;
        
        // Find similar incidents in history
        let similar_incidents = self.find_similar_incidents(incident).await?;
        
        // Determine if this is a novel pattern
        let (is_novel, pattern_signature) = self.assess_novelty(&extracted_patterns, &similar_incidents).await;
        
        // Generate attack description and root cause analysis
        let attack_description = self.generate_attack_description(incident, &extracted_patterns);
        let root_cause = self.analyze_root_cause(incident, &extracted_patterns);
        
        // Calculate confidence score
        let confidence_score = self.calculate_confidence_score(&extracted_patterns, &similar_incidents);
        
        // Assess severity
        let severity_assessment = self.assess_severity(incident, &extracted_patterns);
        
        // Generate recommendations
        let recommended_actions = self.generate_recommendations(incident, &extracted_patterns, is_novel);
        
        // Extract attack vectors and IoCs
        let attack_vectors = self.extract_attack_vectors(&extracted_patterns);
        let indicators_of_compromise = self.extract_iocs(incident, &extracted_patterns);
        
        // Analyze pattern evolution if applicable
        let pattern_evolution = if !similar_incidents.is_empty() {
            Some(self.analyze_pattern_evolution(incident, &similar_incidents).await?)
        } else {
            None
        };

        // Update pattern database
        if is_novel {
            self.update_pattern_database(incident, &pattern_signature, &extracted_patterns).await?;
        }

        Ok(IncidentAnalysis {
            incident_id: incident.id.clone(),
            is_novel_pattern: is_novel,
            pattern_signature,
            attack_description,
            root_cause,
            confidence_score,
            severity_assessment,
            similar_incidents: similar_incidents.iter().map(|i| i.id.clone()).collect(),
            recommended_actions,
            attack_vectors,
            indicators_of_compromise,
            pattern_evolution,
        })
    }

    /// Extract patterns using all available extractors
    async fn extract_all_patterns(&self, incident: &SecurityIncident) -> Vec<ExtractedPattern> {
        let mut all_patterns = Vec::new();
        
        for extractor in &self.pattern_extractors {
            let patterns = extractor.extract_patterns(incident);
            all_patterns.extend(patterns);
        }
        
        // Sort by confidence score
        all_patterns.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        
        all_patterns
    }

    /// Find similar incidents in the database
    async fn find_similar_incidents(&self, incident: &SecurityIncident) -> Result<Vec<SecurityIncident>, AnalyzerError> {
        // This would query the incident database for similar incidents
        // For now, return empty vector as placeholder
        Ok(Vec::new())
    }

    /// Assess if the incident represents a novel pattern
    async fn assess_novelty(&self, patterns: &[ExtractedPattern], similar_incidents: &[SecurityIncident]) -> (bool, String) {
        if similar_incidents.is_empty() {
            // No similar incidents found - likely novel
            let signature = self.generate_pattern_signature(patterns);
            return (true, signature);
        }

        // Check if any extracted patterns are significantly different
        let signature = self.generate_pattern_signature(patterns);
        let pattern_db = self.pattern_database.read().await;
        
        let is_novel = !pattern_db.values().any(|existing_pattern| {
            self.calculate_pattern_similarity(&signature, &existing_pattern.signature) > self.similarity_threshold
        });

        (is_novel, signature)
    }

    /// Generate a unique signature for the pattern
    fn generate_pattern_signature(&self, patterns: &[ExtractedPattern]) -> String {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        
        // Combine all pattern signatures
        for pattern in patterns {
            hasher.update(pattern.signature.as_bytes());
            hasher.update(format!("{:?}", pattern.pattern_type).as_bytes());
        }
        
        format!("{:x}", hasher.finalize())[..16].to_string()
    }

    /// Calculate similarity between two pattern signatures
    fn calculate_pattern_similarity(&self, sig1: &str, sig2: &str) -> f64 {
        // Simple Levenshtein distance-based similarity
        let distance = levenshtein::levenshtein(sig1, sig2);
        let max_len = sig1.len().max(sig2.len());
        
        if max_len == 0 {
            1.0
        } else {
            1.0 - (distance as f64 / max_len as f64)
        }
    }

    /// Generate human-readable attack description
    fn generate_attack_description(&self, incident: &SecurityIncident, patterns: &[ExtractedPattern]) -> String {
        if patterns.is_empty() {
            return format!("Unclassified {} incident", incident.incident_type);
        }

        let primary_pattern = &patterns[0];
        let attack_type = format!("{:?}", primary_pattern.pattern_type).replace("_", " ").to_lowercase();
        
        format!(
            "Detected {} attack using {} technique. The attack attempted to {} through {}.",
            attack_type,
            primary_pattern.features.get("technique").unwrap_or(&"unknown".to_string()),
            primary_pattern.features.get("objective").unwrap_or(&"compromise system".to_string()),
            incident.attack_vector
        )
    }

    /// Analyze root cause of the incident
    fn analyze_root_cause(&self, incident: &SecurityIncident, patterns: &[ExtractedPattern]) -> String {
        let mut root_causes = Vec::new();

        // Analyze based on incident type
        match incident.incident_type {
            IncidentType::PromptInjection => {
                root_causes.push("Insufficient input validation and sanitization".to_string());
                root_causes.push("Lack of prompt injection detection mechanisms".to_string());
            }
            IncidentType::PolicyBypass => {
                root_causes.push("Incomplete policy coverage for edge cases".to_string());
                root_causes.push("Policy logic gaps allowing evasion".to_string());
            }
            IncidentType::EncodingEvasion => {
                root_causes.push("Missing encoding normalization in input processing".to_string());
                root_causes.push("Inadequate character set validation".to_string());
            }
            _ => {
                root_causes.push("Generic security control bypass".to_string());
            }
        }

        // Add pattern-specific root causes
        for pattern in patterns {
            if let Some(cause) = pattern.features.get("root_cause") {
                root_causes.push(cause.clone());
            }
        }

        root_causes.join("; ")
    }

    /// Calculate confidence score for the analysis
    fn calculate_confidence_score(&self, patterns: &[ExtractedPattern], similar_incidents: &[SecurityIncident]) -> f64 {
        if patterns.is_empty() {
            return 0.1;
        }

        let pattern_confidence = patterns.iter().map(|p| p.confidence).sum::<f64>() / patterns.len() as f64;
        let similarity_boost = if similar_incidents.is_empty() { 0.0 } else { 0.2 };
        
        (pattern_confidence + similarity_boost).min(1.0)
    }

    /// Assess incident severity
    fn assess_severity(&self, incident: &SecurityIncident, patterns: &[ExtractedPattern]) -> IncidentSeverity {
        let mut severity_score = match incident.severity {
            IncidentSeverity::Low => 1,
            IncidentSeverity::Medium => 2,
            IncidentSeverity::High => 3,
            IncidentSeverity::Critical => 4,
        };

        // Adjust based on patterns
        for pattern in patterns {
            match pattern.pattern_type {
                IncidentType::PromptInjection | IncidentType::PolicyBypass => severity_score += 1,
                IncidentType::PrivilegeEscalation | IncidentType::DataExfiltration => severity_score += 2,
                _ => {}
            }
        }

        match severity_score {
            1..=2 => IncidentSeverity::Low,
            3..=4 => IncidentSeverity::Medium,
            5..=6 => IncidentSeverity::High,
            _ => IncidentSeverity::Critical,
        }
    }

    /// Generate recommendations for preventing similar incidents
    fn generate_recommendations(&self, incident: &SecurityIncident, patterns: &[ExtractedPattern], is_novel: bool) -> Vec<String> {
        let mut recommendations = Vec::new();

        if is_novel {
            recommendations.push("Create new policy rule to detect this attack pattern".to_string());
            recommendations.push("Update threat intelligence database with new indicators".to_string());
        }

        // Pattern-specific recommendations
        for pattern in patterns {
            match pattern.pattern_type {
                IncidentType::PromptInjection => {
                    recommendations.push("Implement prompt injection detection filters".to_string());
                    recommendations.push("Add input sanitization for LLM interactions".to_string());
                }
                IncidentType::PolicyBypass => {
                    recommendations.push("Review and strengthen policy logic".to_string());
                    recommendations.push("Add additional validation layers".to_string());
                }
                IncidentType::EncodingEvasion => {
                    recommendations.push("Implement Unicode normalization".to_string());
                    recommendations.push("Add encoding detection and validation".to_string());
                }
                _ => {
                    recommendations.push("Strengthen general security controls".to_string());
                }
            }
        }

        // Remove duplicates
        recommendations.sort();
        recommendations.dedup();
        recommendations
    }

    /// Extract attack vectors from patterns
    fn extract_attack_vectors(&self, patterns: &[ExtractedPattern]) -> Vec<String> {
        let mut vectors = HashSet::new();
        
        for pattern in patterns {
            if let Some(vector) = pattern.features.get("attack_vector") {
                vectors.insert(vector.clone());
            }
            
            // Add pattern-specific vectors
            match pattern.pattern_type {
                IncidentType::PromptInjection => vectors.insert("LLM Input".to_string()),
                IncidentType::PolicyBypass => vectors.insert("Policy Engine".to_string()),
                IncidentType::EncodingEvasion => vectors.insert("Input Encoding".to_string()),
                _ => {}
            };
        }
        
        vectors.into_iter().collect()
    }

    /// Extract indicators of compromise
    fn extract_iocs(&self, incident: &SecurityIncident, patterns: &[ExtractedPattern]) -> Vec<String> {
        let mut iocs = Vec::new();
        
        // Extract from incident payload
        iocs.extend(self.extract_payload_iocs(&incident.payload));
        
        // Extract from patterns
        for pattern in patterns {
            iocs.extend(pattern.indicators.clone());
        }
        
        iocs.sort();
        iocs.dedup();
        iocs
    }

    /// Extract IoCs from payload
    fn extract_payload_iocs(&self, payload: &str) -> Vec<String> {
        let mut iocs = Vec::new();
        
        // SQL injection indicators
        let sql_patterns = vec![
            r"(?i)(union\s+select)",
            r"(?i)(drop\s+table)",
            r"(?i)(or\s+1\s*=\s*1)",
            r"(?i)(';?\s*--)",
        ];
        
        for pattern in sql_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(payload) {
                    iocs.push(format!("SQL injection pattern: {}", pattern));
                }
            }
        }
        
        // Command injection indicators
        let cmd_patterns = vec![
            r"(?i)(;\s*rm\s+-rf)",
            r"(?i)(&&\s*cat\s+/etc/passwd)",
            r"(?i)(\|\s*nc\s+)",
        ];
        
        for pattern in cmd_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(payload) {
                    iocs.push(format!("Command injection pattern: {}", pattern));
                }
            }
        }
        
        iocs
    }

    /// Analyze pattern evolution
    async fn analyze_pattern_evolution(&self, incident: &SecurityIncident, similar_incidents: &[SecurityIncident]) -> Result<PatternEvolution, AnalyzerError> {
        if similar_incidents.is_empty() {
            return Err(AnalyzerError::InsufficientData("No similar incidents for evolution analysis".to_string()));
        }

        let base_incident = &similar_incidents[0];
        let evolution_type = self.determine_evolution_type(incident, base_incident);
        let new_techniques = self.identify_new_techniques(incident, similar_incidents);
        let evasion_methods = self.identify_evasion_methods(incident, similar_incidents);
        let complexity_increase = self.calculate_complexity_increase(incident, base_incident);

        Ok(PatternEvolution {
            base_pattern_id: base_incident.id.clone(),
            evolution_type,
            new_techniques,
            evasion_methods,
            complexity_increase,
        })
    }

    /// Determine the type of pattern evolution
    fn determine_evolution_type(&self, current: &SecurityIncident, base: &SecurityIncident) -> EvolutionType {
        let payload_similarity = self.calculate_pattern_similarity(&current.payload, &base.payload);
        
        if payload_similarity > 0.8 {
            EvolutionType::Mutation
        } else if payload_similarity > 0.5 {
            EvolutionType::Sophistication
        } else if current.bypass_technique.is_some() && base.bypass_technique.is_none() {
            EvolutionType::Evasion
        } else {
            EvolutionType::Novel
        }
    }

    /// Identify new techniques in the evolved pattern
    fn identify_new_techniques(&self, current: &SecurityIncident, similar: &[SecurityIncident]) -> Vec<String> {
        let mut new_techniques = Vec::new();
        
        // Compare attack vectors
        let existing_vectors: HashSet<_> = similar.iter().map(|i| &i.attack_vector).collect();
        if !existing_vectors.contains(&current.attack_vector) {
            new_techniques.push(format!("New attack vector: {}", current.attack_vector));
        }
        
        // Compare bypass techniques
        if let Some(bypass) = &current.bypass_technique {
            let existing_bypasses: HashSet<_> = similar.iter()
                .filter_map(|i| i.bypass_technique.as_ref())
                .collect();
            if !existing_bypasses.contains(bypass) {
                new_techniques.push(format!("New bypass technique: {}", bypass));
            }
        }
        
        new_techniques
    }

    /// Identify evasion methods
    fn identify_evasion_methods(&self, current: &SecurityIncident, similar: &[SecurityIncident]) -> Vec<String> {
        let mut evasion_methods = Vec::new();
        
        // Check for encoding evasion
        if current.payload.chars().any(|c| c as u32 > 127) {
            evasion_methods.push("Unicode encoding evasion".to_string());
        }
        
        // Check for obfuscation
        if current.payload.len() > similar.iter().map(|i| i.payload.len()).max().unwrap_or(0) * 2 {
            evasion_methods.push("Payload obfuscation".to_string());
        }
        
        evasion_methods
    }

    /// Calculate complexity increase
    fn calculate_complexity_increase(&self, current: &SecurityIncident, base: &SecurityIncident) -> f64 {
        let length_ratio = current.payload.len() as f64 / base.payload.len().max(1) as f64;
        let metadata_increase = current.metadata.len() as f64 / base.metadata.len().max(1) as f64;
        
        (length_ratio + metadata_increase) / 2.0
    }

    /// Update pattern database with new pattern
    async fn update_pattern_database(&self, incident: &SecurityIncident, signature: &str, patterns: &[ExtractedPattern]) -> Result<(), AnalyzerError> {
        let mut pattern_db = self.pattern_database.write().await;
        
        let attack_pattern = AttackPattern {
            pattern_id: signature.clone(),
            pattern_type: incident.incident_type.clone(),
            signature: signature.clone(),
            variants: patterns.iter().map(|p| p.signature.clone()).collect(),
            frequency: 1,
            last_seen: incident.timestamp,
            mitigation_strategies: self.generate_mitigation_strategies(patterns),
        };
        
        pattern_db.insert(signature.clone(), attack_pattern);
        
        println!("📊 Updated pattern database with new pattern: {}", signature);
        Ok(())
    }

    /// Generate mitigation strategies for patterns
    fn generate_mitigation_strategies(&self, patterns: &[ExtractedPattern]) -> Vec<String> {
        let mut strategies = Vec::new();
        
        for pattern in patterns {
            match pattern.pattern_type {
                IncidentType::PromptInjection => {
                    strategies.push("Implement prompt injection filters".to_string());
                    strategies.push("Add input length limits".to_string());
                }
                IncidentType::PolicyBypass => {
                    strategies.push("Strengthen policy validation".to_string());
                    strategies.push("Add multi-layer policy checks".to_string());
                }
                IncidentType::EncodingEvasion => {
                    strategies.push("Normalize all input encodings".to_string());
                    strategies.push("Validate character sets".to_string());
                }
                _ => {
                    strategies.push("Apply defense-in-depth principles".to_string());
                }
            }
        }
        
        strategies.sort();
        strategies.dedup();
        strategies
    }
}

/// Analyzer errors
#[derive(Debug, thiserror::Error)]
pub enum AnalyzerError {
    #[error("Insufficient data: {0}")]
    InsufficientData(String),
    
    #[error("Pattern extraction failed: {0}")]
    PatternExtractionFailed(String),
    
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    #[error("ML classification error: {0}")]
    MlError(String),
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            similarity_threshold: 0.8,
            min_pattern_frequency: 3,
            pattern_decay_days: 90,
            ml_classification_enabled: false,
            real_time_analysis: true,
            pattern_clustering_enabled: true,
        }
    }
}

// Pattern extractor implementations
pub struct PromptInjectionExtractor;

impl PromptInjectionExtractor {
    pub fn new() -> Self {
        Self
    }
}

impl PatternExtractor for PromptInjectionExtractor {
    fn extract_patterns(&self, incident: &SecurityIncident) -> Vec<ExtractedPattern> {
        let mut patterns = Vec::new();
        
        if incident.incident_type == IncidentType::PromptInjection {
            let mut features = HashMap::new();
            features.insert("technique".to_string(), "prompt_injection".to_string());
            features.insert("objective".to_string(), "bypass_llm_safety".to_string());
            
            let pattern = ExtractedPattern {
                pattern_type: IncidentType::PromptInjection,
                signature: format!("prompt_injection_{}", incident.payload.len()),
                features,
                confidence: 0.9,
                indicators: vec!["Ignore previous instructions".to_string(), "System prompt override".to_string()],
            };
            
            patterns.push(pattern);
        }
        
        patterns
    }
    
    fn get_pattern_type(&self) -> IncidentType {
        IncidentType::PromptInjection
    }
    
    fn get_confidence(&self, _pattern: &str) -> f64 {
        0.8
    }
}

// Additional pattern extractors would be implemented similarly
pub struct SqlInjectionExtractor;
impl SqlInjectionExtractor { pub fn new() -> Self { Self } }
impl PatternExtractor for SqlInjectionExtractor {
    fn extract_patterns(&self, _incident: &SecurityIncident) -> Vec<ExtractedPattern> { Vec::new() }
    fn get_pattern_type(&self) -> IncidentType { IncidentType::NovelAttack }
    fn get_confidence(&self, _pattern: &str) -> f64 { 0.7 }
}

pub struct XssExtractor;
impl XssExtractor { pub fn new() -> Self { Self } }
impl PatternExtractor for XssExtractor {
    fn extract_patterns(&self, _incident: &SecurityIncident) -> Vec<ExtractedPattern> { Vec::new() }
    fn get_pattern_type(&self) -> IncidentType { IncidentType::NovelAttack }
    fn get_confidence(&self, _pattern: &str) -> f64 { 0.7 }
}

pub struct CommandInjectionExtractor;
impl CommandInjectionExtractor { pub fn new() -> Self { Self } }
impl PatternExtractor for CommandInjectionExtractor {
    fn extract_patterns(&self, _incident: &SecurityIncident) -> Vec<ExtractedPattern> { Vec::new() }
    fn get_pattern_type(&self) -> IncidentType { IncidentType::NovelAttack }
    fn get_confidence(&self, _pattern: &str) -> f64 { 0.7 }
}

pub struct EncodingEvasionExtractor;
impl EncodingEvasionExtractor { pub fn new() -> Self { Self } }
impl PatternExtractor for EncodingEvasionExtractor {
    fn extract_patterns(&self, _incident: &SecurityIncident) -> Vec<ExtractedPattern> { Vec::new() }
    fn get_pattern_type(&self) -> IncidentType { IncidentType::EncodingEvasion }
    fn get_confidence(&self, _pattern: &str) -> f64 { 0.8 }
}

pub struct PolicyBypassExtractor;
impl PolicyBypassExtractor { pub fn new() -> Self { Self } }
impl PatternExtractor for PolicyBypassExtractor {
    fn extract_patterns(&self, _incident: &SecurityIncident) -> Vec<ExtractedPattern> { Vec::new() }
    fn get_pattern_type(&self) -> IncidentType { IncidentType::PolicyBypass }
    fn get_confidence(&self, _pattern: &str) -> f64 { 0.8 }
}
