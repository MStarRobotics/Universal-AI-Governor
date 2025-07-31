//! Universal AI Governor - Main Application Entry Point
//!
//! This is the main HTTP server that provides the REST API for the Universal AI Governor.
//! It uses Axum as the web framework for high performance and excellent ergonomics.

use axum::{
    response::Json,
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
};
use tracing::info;
use tracing_subscriber::fmt;

// Import our library modules
use universal_ai_governor::config::Config;

#[derive(Debug, Serialize, Deserialize)]
struct HealthResponse {
    status: String,
    service: String,
    version: String,
    timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Policy {
    id: String,
    name: String,
    description: String,
    enabled: bool,
    rules: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: String,
    username: String,
    email: String,
    roles: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuditLog {
    id: String,
    user_id: String,
    action: String,
    resource: String,
    timestamp: String,
    details: HashMap<String, Value>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    fmt::init();

    info!("Starting Universal AI Governor server...");

    // Load configuration
    let config = Config::default();
    
    // Build our application with routes
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/policies", get(get_policies))
        .route("/api/v1/users", get(get_users))
        .route("/api/v1/audit", get(get_audit_logs))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive())
        );

    // Start the server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    info!("Server listening on {}", addr);
    
    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Health check endpoint
async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        service: "universal-ai-governor".to_string(),
        version: "1.0.0".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

/// Get all policies
async fn get_policies() -> Json<Vec<Policy>> {
    // Mock data for now
    let policies = vec![
        Policy {
            id: "1".to_string(),
            name: "Default Policy".to_string(),
            description: "Default AI governance policy".to_string(),
            enabled: true,
            rules: HashMap::new(),
        },
        Policy {
            id: "2".to_string(),
            name: "Strict Policy".to_string(),
            description: "Strict AI governance policy with enhanced security".to_string(),
            enabled: true,
            rules: {
                let mut rules = HashMap::new();
                rules.insert("max_tokens".to_string(), json!(1000));
                rules.insert("require_approval".to_string(), json!(true));
                rules
            },
        },
    ];
    
    Json(policies)
}

/// Get all users
async fn get_users() -> Json<Vec<User>> {
    // Mock data for now
    let users = vec![
        User {
            id: "1".to_string(),
            username: "admin".to_string(),
            email: "admin@example.com".to_string(),
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        User {
            id: "2".to_string(),
            username: "analyst".to_string(),
            email: "analyst@example.com".to_string(),
            roles: vec!["analyst".to_string(), "user".to_string()],
        },
    ];
    
    Json(users)
}

/// Get audit logs
async fn get_audit_logs() -> Json<Vec<AuditLog>> {
    // Mock data for now
    let logs = vec![
        AuditLog {
            id: "1".to_string(),
            user_id: "admin".to_string(),
            action: "login".to_string(),
            resource: "system".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            details: {
                let mut details = HashMap::new();
                details.insert("ip_address".to_string(), json!("127.0.0.1"));
                details.insert("user_agent".to_string(), json!("Mozilla/5.0"));
                details
            },
        },
        AuditLog {
            id: "2".to_string(),
            user_id: "analyst".to_string(),
            action: "policy_view".to_string(),
            resource: "policy:1".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            details: HashMap::new(),
        },
    ];
    
    Json(logs)
}
