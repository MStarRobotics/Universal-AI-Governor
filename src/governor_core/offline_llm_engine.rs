// Offline LLM Engine for Policy Generation
// Runs local LLM models for secure policy synthesis without external API calls

use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

/// Offline LLM engine using llama.cpp or Ollama
pub struct OfflineLlmEngine {
    model_path: String,
    engine_type: LlmEngineType,
    model_config: ModelConfig,
    conversation_history: RwLock<Vec<ConversationTurn>>,
    prompt_templates: HashMap<String, PromptTemplate>,
}

/// Types of LLM engines supported
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LlmEngineType {
    LlamaCpp,
    Ollama,
    Candle,
    LocalGpt,
}

/// Configuration for the LLM model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    pub context_window: usize,
    pub temperature: f32,
    pub top_p: f32,
    pub top_k: i32,
    pub max_tokens: usize,
    pub repeat_penalty: f32,
    pub seed: Option<u64>,
    pub threads: usize,
}

/// Conversation turn for context management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationTurn {
    pub role: Role,
    pub content: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Roles in conversation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Role {
    System,
    User,
    Assistant,
}

/// Prompt template for different tasks
#[derive(Debug, Clone)]
pub struct PromptTemplate {
    pub name: String,
    pub system_prompt: String,
    pub user_template: String,
    pub expected_format: String,
    pub examples: Vec<PromptExample>,
}

/// Example for few-shot prompting
#[derive(Debug, Clone)]
pub struct PromptExample {
    pub input: String,
    pub output: String,
    pub explanation: String,
}

/// LLM generation result
#[derive(Debug, Clone)]
pub struct LlmResponse {
    pub content: String,
    pub confidence_score: f64,
    pub tokens_used: usize,
    pub generation_time_ms: u64,
    pub model_info: ModelInfo,
}

/// Information about the model used
#[derive(Debug, Clone)]
pub struct ModelInfo {
    pub model_name: String,
    pub model_size: String,
    pub quantization: Option<String>,
    pub context_length: usize,
}

impl OfflineLlmEngine {
    /// Initialize the offline LLM engine
    pub async fn new(model_path: &str) -> Result<Self, LlmEngineError> {
        let engine_type = Self::detect_engine_type(model_path)?;
        let model_config = ModelConfig::default();
        let prompt_templates = Self::load_prompt_templates();

        // Verify model accessibility
        Self::verify_model_access(model_path, &engine_type).await?;

        Ok(Self {
            model_path: model_path.to_string(),
            engine_type,
            model_config,
            conversation_history: RwLock::new(Vec::new()),
            prompt_templates,
        })
    }

    /// Detect the type of LLM engine based on model path
    fn detect_engine_type(model_path: &str) -> Result<LlmEngineType, LlmEngineError> {
        if model_path.ends_with(".gguf") || model_path.ends_with(".ggml") {
            Ok(LlmEngineType::LlamaCpp)
        } else if model_path.contains("ollama") || model_path.starts_with("ollama://") {
            Ok(LlmEngineType::Ollama)
        } else if model_path.ends_with(".safetensors") || model_path.ends_with(".bin") {
            Ok(LlmEngineType::Candle)
        } else {
            Ok(LlmEngineType::LlamaCpp) // Default fallback
        }
    }

    /// Verify model accessibility
    async fn verify_model_access(model_path: &str, engine_type: &LlmEngineType) -> Result<(), LlmEngineError> {
        match engine_type {
            LlmEngineType::LlamaCpp => {
                // Check if llama.cpp binary exists
                if !std::path::Path::new("./llama.cpp/main").exists() && 
                   !std::path::Path::new("/usr/local/bin/llama").exists() {
                    return Err(LlmEngineError::EngineNotFound("llama.cpp binary not found".to_string()));
                }
                
                // Check if model file exists
                if !std::path::Path::new(model_path).exists() {
                    return Err(LlmEngineError::ModelNotFound(model_path.to_string()));
                }
            }
            LlmEngineType::Ollama => {
                // Check if Ollama is running
                let output = Command::new("ollama")
                    .args(&["list"])
                    .output();
                
                if output.is_err() {
                    return Err(LlmEngineError::EngineNotFound("Ollama not found or not running".to_string()));
                }
            }
            _ => {
                // Basic file existence check for other engines
                if !std::path::Path::new(model_path).exists() {
                    return Err(LlmEngineError::ModelNotFound(model_path.to_string()));
                }
            }
        }
        
        Ok(())
    }

    /// Load prompt templates for different tasks
    fn load_prompt_templates() -> HashMap<String, PromptTemplate> {
        let mut templates = HashMap::new();

        // Policy generation template
        templates.insert("policy_generation".to_string(), PromptTemplate {
            name: "Policy Generation".to_string(),
            system_prompt: r#"You are a cybersecurity expert specializing in policy generation for AI governance systems. Your task is to analyze security incidents and generate precise Rego policy rules that prevent similar attacks while minimizing false positives.

Key principles:
1. Generate specific, actionable Rego code
2. Include comprehensive test cases
3. Explain the reasoning behind each rule
4. Consider edge cases and variants
5. Optimize for both security and performance

Always respond with valid Rego syntax and JSON test cases."#.to_string(),
            user_template: "{incident_context}".to_string(),
            expected_format: "Rego code block followed by JSON test cases".to_string(),
            examples: vec![
                PromptExample {
                    input: "SQL injection attempt: '; DROP TABLE users; --".to_string(),
                    output: r#"```rego
# Policy: Block SQL Injection Attempts
# Description: Prevents SQL injection by detecting common SQL keywords and patterns
package governor.policies.sql_injection

deny[msg] {
    input.payload
    contains_sql_injection(input.payload)
    msg := "SQL injection attempt detected"
}

contains_sql_injection(payload) {
    lower_payload := lower(payload)
    sql_keywords := ["drop table", "union select", "'; --", "or 1=1"]
    some keyword in sql_keywords
    contains(lower_payload, keyword)
}
```"#.to_string(),
                    explanation: "Detects common SQL injection patterns while avoiding false positives".to_string(),
                },
            ],
        });

        // Incident analysis template
        templates.insert("incident_analysis".to_string(), PromptTemplate {
            name: "Incident Analysis".to_string(),
            system_prompt: r#"You are a security analyst specializing in incident analysis and pattern recognition. Analyze security incidents to identify attack patterns, root causes, and recommend mitigation strategies.

Focus on:
1. Identifying novel attack patterns
2. Understanding the root cause
3. Assessing the severity and impact
4. Recommending specific countermeasures
5. Predicting likely variants of the attack"#.to_string(),
            user_template: "{incident_details}".to_string(),
            expected_format: "Structured analysis with pattern identification and recommendations".to_string(),
            examples: vec![],
        });

        templates
    }

    /// Generate a policy rule for a given incident
    pub async fn generate_policy(&self, context: &str) -> Result<LlmResponse, LlmEngineError> {
        let start_time = std::time::Instant::now();
        
        // Get the policy generation template
        let template = self.prompt_templates.get("policy_generation")
            .ok_or_else(|| LlmEngineError::TemplateNotFound("policy_generation".to_string()))?;

        // Build the full prompt
        let full_prompt = self.build_prompt(template, context).await?;
        
        // Generate response using the appropriate engine
        let response = match self.engine_type {
            LlmEngineType::LlamaCpp => self.generate_with_llama_cpp(&full_prompt).await?,
            LlmEngineType::Ollama => self.generate_with_ollama(&full_prompt).await?,
            LlmEngineType::Candle => self.generate_with_candle(&full_prompt).await?,
            LlmEngineType::LocalGpt => self.generate_with_local_gpt(&full_prompt).await?,
        };

        let generation_time = start_time.elapsed().as_millis() as u64;

        // Update conversation history
        self.add_to_conversation(Role::User, context).await;
        self.add_to_conversation(Role::Assistant, &response.content).await;

        Ok(LlmResponse {
            content: response.content,
            confidence_score: self.calculate_confidence_score(&response.content),
            tokens_used: response.tokens_used,
            generation_time_ms: generation_time,
            model_info: self.get_model_info(),
        })
    }

    /// Build a complete prompt from template and context
    async fn build_prompt(&self, template: &PromptTemplate, context: &str) -> Result<String, LlmEngineError> {
        let mut prompt = String::new();
        
        // Add system prompt
        prompt.push_str(&format!("System: {}\n\n", template.system_prompt));
        
        // Add few-shot examples if available
        for example in &template.examples {
            prompt.push_str(&format!("User: {}\n", example.input));
            prompt.push_str(&format!("Assistant: {}\n\n", example.output));
        }
        
        // Add current context
        prompt.push_str(&format!("User: {}\n", context));
        prompt.push_str("Assistant: ");
        
        Ok(prompt)
    }

    /// Generate response using llama.cpp
    async fn generate_with_llama_cpp(&self, prompt: &str) -> Result<RawLlmResponse, LlmEngineError> {
        // Write prompt to temporary file
        let mut temp_file = NamedTempFile::new()
            .map_err(|e| LlmEngineError::IoError(format!("Failed to create temp file: {}", e)))?;
        
        std::io::Write::write_all(&mut temp_file, prompt.as_bytes())
            .map_err(|e| LlmEngineError::IoError(format!("Failed to write prompt: {}", e)))?;

        // Execute llama.cpp
        let output = Command::new("./llama.cpp/main")
            .args(&[
                "-m", &self.model_path,
                "-f", temp_file.path().to_str().unwrap(),
                "-n", &self.model_config.max_tokens.to_string(),
                "-t", &self.model_config.threads.to_string(),
                "--temp", &self.model_config.temperature.to_string(),
                "--top-p", &self.model_config.top_p.to_string(),
                "--top-k", &self.model_config.top_k.to_string(),
                "--repeat-penalty", &self.model_config.repeat_penalty.to_string(),
                "--ctx-size", &self.model_config.context_window.to_string(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| LlmEngineError::ExecutionError(format!("Failed to execute llama.cpp: {}", e)))?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(LlmEngineError::ExecutionError(format!("llama.cpp failed: {}", error)));
        }

        let response_text = String::from_utf8_lossy(&output.stdout).to_string();
        
        Ok(RawLlmResponse {
            content: self.clean_llama_cpp_output(&response_text),
            tokens_used: self.estimate_token_count(&response_text),
        })
    }

    /// Generate response using Ollama
    async fn generate_with_ollama(&self, prompt: &str) -> Result<RawLlmResponse, LlmEngineError> {
        // Extract model name from path (e.g., "ollama://llama2:7b" -> "llama2:7b")
        let model_name = self.model_path.strip_prefix("ollama://").unwrap_or(&self.model_path);

        let output = Command::new("ollama")
            .args(&[
                "generate",
                model_name,
                prompt,
                "--format", "json",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| LlmEngineError::ExecutionError(format!("Failed to execute Ollama: {}", e)))?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(LlmEngineError::ExecutionError(format!("Ollama failed: {}", error)));
        }

        let response_text = String::from_utf8_lossy(&output.stdout).to_string();
        
        Ok(RawLlmResponse {
            content: response_text,
            tokens_used: self.estimate_token_count(&response_text),
        })
    }

    /// Generate response using Candle
    async fn generate_with_candle(&self, prompt: &str) -> Result<RawLlmResponse, LlmEngineError> {
        // This would integrate with the Candle ML framework
        // For now, return a placeholder
        Err(LlmEngineError::NotImplemented("Candle engine not yet implemented".to_string()))
    }

    /// Generate response using LocalGPT
    async fn generate_with_local_gpt(&self, prompt: &str) -> Result<RawLlmResponse, LlmEngineError> {
        // This would integrate with LocalGPT
        // For now, return a placeholder
        Err(LlmEngineError::NotImplemented("LocalGPT engine not yet implemented".to_string()))
    }

    /// Clean llama.cpp output to extract just the generated text
    fn clean_llama_cpp_output(&self, raw_output: &str) -> String {
        // Remove llama.cpp metadata and keep only the generated text
        let lines: Vec<&str> = raw_output.lines().collect();
        let mut content_started = false;
        let mut cleaned_lines = Vec::new();

        for line in lines {
            if line.starts_with("Assistant:") {
                content_started = true;
                cleaned_lines.push(line.strip_prefix("Assistant:").unwrap_or(line).trim());
            } else if content_started && !line.starts_with("llama_") && !line.contains("tokens per second") {
                cleaned_lines.push(line);
            }
        }

        cleaned_lines.join("\n").trim().to_string()
    }

    /// Estimate token count for a given text
    fn estimate_token_count(&self, text: &str) -> usize {
        // Simple estimation: ~4 characters per token for English text
        (text.len() as f64 / 4.0).ceil() as usize
    }

    /// Calculate confidence score based on response quality
    fn calculate_confidence_score(&self, response: &str) -> f64 {
        let mut score = 0.5; // Base score

        // Check for Rego code presence
        if response.contains("```rego") && response.contains("package ") {
            score += 0.2;
        }

        // Check for test cases
        if response.contains("```json") || response.contains("test") {
            score += 0.1;
        }

        // Check for policy structure
        if response.contains("deny[") || response.contains("allow[") {
            score += 0.1;
        }

        // Check for comments and documentation
        if response.contains("#") && response.contains("Description:") {
            score += 0.1;
        }

        // Penalize very short responses
        if response.len() < 100 {
            score -= 0.2;
        }

        score.max(0.0).min(1.0)
    }

    /// Get model information
    fn get_model_info(&self) -> ModelInfo {
        ModelInfo {
            model_name: std::path::Path::new(&self.model_path)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            model_size: "Unknown".to_string(), // Would be determined from model metadata
            quantization: if self.model_path.contains("q4") {
                Some("Q4_0".to_string())
            } else if self.model_path.contains("q8") {
                Some("Q8_0".to_string())
            } else {
                None
            },
            context_length: self.model_config.context_window,
        }
    }

    /// Add message to conversation history
    async fn add_to_conversation(&self, role: Role, content: &str) {
        let mut history = self.conversation_history.write().await;
        history.push(ConversationTurn {
            role,
            content: content.to_string(),
            timestamp: chrono::Utc::now(),
        });

        // Keep only recent conversation history
        if history.len() > 10 {
            history.remove(0);
        }
    }

    /// Analyze an incident using the LLM
    pub async fn analyze_incident(&self, incident_details: &str) -> Result<LlmResponse, LlmEngineError> {
        let template = self.prompt_templates.get("incident_analysis")
            .ok_or_else(|| LlmEngineError::TemplateNotFound("incident_analysis".to_string()))?;

        let full_prompt = self.build_prompt(template, incident_details).await?;
        
        let response = match self.engine_type {
            LlmEngineType::LlamaCpp => self.generate_with_llama_cpp(&full_prompt).await?,
            LlmEngineType::Ollama => self.generate_with_ollama(&full_prompt).await?,
            _ => return Err(LlmEngineError::NotImplemented("Engine not implemented for incident analysis".to_string())),
        };

        Ok(LlmResponse {
            content: response.content,
            confidence_score: self.calculate_confidence_score(&response.content),
            tokens_used: response.tokens_used,
            generation_time_ms: 0, // Would be calculated
            model_info: self.get_model_info(),
        })
    }

    /// Get conversation history
    pub async fn get_conversation_history(&self) -> Vec<ConversationTurn> {
        let history = self.conversation_history.read().await;
        history.clone()
    }

    /// Clear conversation history
    pub async fn clear_conversation_history(&self) {
        let mut history = self.conversation_history.write().await;
        history.clear();
    }
}

/// Raw response from LLM engine
#[derive(Debug)]
struct RawLlmResponse {
    content: String,
    tokens_used: usize,
}

/// LLM engine errors
#[derive(Debug, thiserror::Error)]
pub enum LlmEngineError {
    #[error("Engine not found: {0}")]
    EngineNotFound(String),
    
    #[error("Model not found: {0}")]
    ModelNotFound(String),
    
    #[error("Template not found: {0}")]
    TemplateNotFound(String),
    
    #[error("Execution error: {0}")]
    ExecutionError(String),
    
    #[error("IO error: {0}")]
    IoError(String),
    
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            context_window: 4096,
            temperature: 0.7,
            top_p: 0.9,
            top_k: 40,
            max_tokens: 1024,
            repeat_penalty: 1.1,
            seed: None,
            threads: num_cpus::get(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_type_detection() {
        assert_eq!(
            OfflineLlmEngine::detect_engine_type("model.gguf").unwrap(),
            LlmEngineType::LlamaCpp
        );
        assert_eq!(
            OfflineLlmEngine::detect_engine_type("ollama://llama2:7b").unwrap(),
            LlmEngineType::Ollama
        );
    }

    #[test]
    fn test_token_estimation() {
        let engine = OfflineLlmEngine {
            model_path: "test".to_string(),
            engine_type: LlmEngineType::LlamaCpp,
            model_config: ModelConfig::default(),
            conversation_history: RwLock::new(Vec::new()),
            prompt_templates: HashMap::new(),
        };
        
        assert_eq!(engine.estimate_token_count("hello world"), 3);
        assert_eq!(engine.estimate_token_count("a".repeat(100).as_str()), 25);
    }

    #[tokio::test]
    async fn test_conversation_history() {
        let engine = OfflineLlmEngine {
            model_path: "test".to_string(),
            engine_type: LlmEngineType::LlamaCpp,
            model_config: ModelConfig::default(),
            conversation_history: RwLock::new(Vec::new()),
            prompt_templates: HashMap::new(),
        };
        
        engine.add_to_conversation(Role::User, "test message").await;
        let history = engine.get_conversation_history().await;
        
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].content, "test message");
    }
}
