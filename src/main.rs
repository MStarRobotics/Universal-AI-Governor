use clap::{Arg, Command};
use std::path::PathBuf;
use tokio;
use tracing::{info, error};
use universal_ai_governor::{GovernorConfig, GovernorCore, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Set up command line argument parsing
    let matches = Command::new("universal-ai-governor")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Sourav Rajak <morningstar.xcd@gmail.com>")
        .about("Hardware-backed AI governance platform")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .default_value("config/default.toml")
        )
        .arg(
            Arg::new("validate")
                .long("validate")
                .help("Validate configuration and exit")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose logging")
                .action(clap::ArgAction::Count)
        )
        .get_matches();

    // Initialize logging based on verbosity
    let log_level = match matches.get_count("verbose") {
        0 => "info",
        1 => "debug", 
        _ => "trace",
    };
    
    // TODO: This is a bit hacky, should probably use a proper logging config
    std::env::set_var("RUST_LOG", log_level);
    tracing_subscriber::fmt::init();

    info!("Starting Universal AI Governor v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config_path = PathBuf::from(matches.get_one::<String>("config").unwrap());
    let config = match GovernorConfig::from_file(&config_path) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration from {:?}: {}", config_path, e);
            std::process::exit(1);
        }
    };

    // If we're just validating config, do that and exit
    if matches.get_flag("validate") {
        match config.validate() {
            Ok(()) => {
                info!("Configuration is valid");
                return Ok(());
            }
            Err(e) => {
                error!("Configuration validation failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Initialize the governor core
    info!("Initializing governor core...");
    let governor = match GovernorCore::new(config).await {
        Ok(governor) => governor,
        Err(e) => {
            error!("Failed to initialize governor: {}", e);
            std::process::exit(1);
        }
    };

    // Set up signal handling for graceful shutdown
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
        info!("Received shutdown signal");
    };

    // Start the server
    info!("Starting server...");
    tokio::select! {
        result = governor.run() => {
            match result {
                Ok(()) => info!("Server stopped normally"),
                Err(e) => error!("Server error: {}", e),
            }
        }
        _ = shutdown_signal => {
            info!("Initiating graceful shutdown...");
        }
    }

    // Perform cleanup
    info!("Shutting down...");
    governor.shutdown().await?;
    info!("Shutdown complete");

    Ok(())
}
