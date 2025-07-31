//! Universal AI Governor main binary

use universal_ai_governor::{config::Config, Result};
use clap::{Arg, Command};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let matches = Command::new("universal-ai-governor")
        .version(universal_ai_governor::VERSION)
        .about("Hardware-backed AI governance platform")
        .arg(
            Arg::new("config")
                .long("config")
                .short('c')
                .value_name("FILE")
                .help("Configuration file path")
                .value_parser(clap::value_parser!(PathBuf))
        )
        .get_matches();

    // Load configuration
    let config = if let Some(config_path) = matches.get_one::<PathBuf>("config") {
        Config::from_file(config_path)?
    } else {
        Config::default()
    };

    tracing::info!("Starting Universal AI Governor v{}", universal_ai_governor::VERSION);
    tracing::info!("Server will listen on {}:{}", config.server.host, config.server.port);

    // Start the server
    start_server(config).await?;

    Ok(())
}

async fn start_server(config: Config) -> Result<()> {
    use axum::{
        routing::get,
        Router,
        Json,
        response::Json as ResponseJson,
    };
    use serde_json::{json, Value};
    use std::net::SocketAddr;

    // Create router
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/policies", get(get_policies))
        .route("/api/v1/users", get(get_users))
        .route("/api/v1/audit", get(get_audit_logs));

    // Create socket address
    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .map_err(|e| universal_ai_governor::GovernorError::Config(e.to_string()))?;

    tracing::info!("Server listening on {}", addr);

    // Start server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> ResponseJson<Value> {
    ResponseJson(json!({
        "status": "healthy",
        "service": "universal-ai-governor",
        "version": universal_ai_governor::VERSION
    }))
}

async fn get_policies() -> ResponseJson<Value> {
    ResponseJson(json!([
        {
            "id": "1",
            "name": "Default Policy",
            "description": "Default AI governance policy",
            "enabled": true
        }
    ]))
}

async fn get_users() -> ResponseJson<Value> {
    ResponseJson(json!([
        {
            "id": "1",
            "username": "admin",
            "email": "admin@example.com",
            "roles": ["admin"]
        }
    ]))
}

async fn get_audit_logs() -> ResponseJson<Value> {
    ResponseJson(json!([
        {
            "id": "1",
            "user_id": "1",
            "action": "login",
            "resource": "system",
            "timestamp": chrono::Utc::now().to_rfc3339()
        }
    ]))
}
