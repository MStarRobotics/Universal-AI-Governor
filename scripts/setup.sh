#!/bin/bash
# Universal AI Governor - Setup Script
# 
# I got tired of explaining to people how to set up the development environment,
# so I automated it. This should work on most Unix-like systems.

set -euo pipefail

# Colors for output (because plain text is boring)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Simple logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Print a nice banner because why not
print_banner() {
    echo -e "${BLUE}"
    echo "+================================================================+"
    echo "|                                                                |"
    echo "|              UNIVERSAL AI GOVERNOR SETUP                      |"
    echo "|                                                                |"
    echo "|         Setting up your development environment               |"
    echo "|                                                                |"
    echo "+================================================================+"
    echo -e "${NC}"
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Figure out what OS we're running on
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt-get; then
            echo "ubuntu"
        elif command_exists yum; then
            echo "centos"
        elif command_exists pacman; then
            echo "arch"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

# Install Rust if it's not already there
install_rust() {
    if command_exists rustc; then
        log_info "Rust is already installed ($(rustc --version))"
        return
    fi

    log_info "Installing Rust... (this might take a few minutes)"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
    log_success "Rust installed successfully"
}

# Install system dependencies based on the OS
install_system_deps() {
    local os=$(detect_os)
    log_info "Installing system dependencies for $os..."

    case $os in
        ubuntu)
            sudo apt-get update
            sudo apt-get install -y \
                build-essential \
                pkg-config \
                libssl-dev \
                libtss2-dev \
                tpm2-tools \
                libopencv-dev \
                libclang-dev \
                curl \
                git
            ;;
        centos)
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y \
                pkg-config \
                openssl-devel \
                tpm2-tss-devel \
                tpm2-tools \
                opencv-devel \
                clang-devel \
                curl \
                git
            ;;
        arch)
            sudo pacman -S --noconfirm \
                base-devel \
                pkg-config \
                openssl \
                tpm2-tss \
                tpm2-tools \
                opencv \
                clang \
                curl \
                git
            ;;
        macos)
            if ! command_exists brew; then
                log_info "Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install \
                pkg-config \
                openssl \
                tpm2-tools \
                opencv \
                llvm
            ;;
        *)
            log_warning "Unknown operating system. You'll need to install dependencies manually."
            log_info "Required packages: build tools, pkg-config, openssl-dev, tpm2-tss-dev, opencv-dev"
            ;;
    esac

    log_success "System dependencies installed"
}

# Install useful Rust development tools
install_rust_tools() {
    log_info "Installing Rust development tools..."
    
    # Essential tools that I use all the time
    cargo install cargo-watch cargo-edit cargo-audit cargo-deny
    
    # Testing and coverage (these are optional but really useful)
    cargo install cargo-tarpaulin cargo-nextest || log_warning "Some testing tools failed to install (this is usually fine)"
    
    # Performance tools
    cargo install cargo-criterion flamegraph || log_warning "Some performance tools failed to install"
    
    # Documentation tools
    cargo install mdbook mdbook-mermaid || log_warning "Documentation tools failed to install"
    
    log_success "Rust tools installed (some failures are normal)"
}

# Create the directory structure we need
create_directories() {
    log_info "Creating project directories..."
    
    mkdir -p {data,logs,models,keys,certs,tmp}
    mkdir -p config/{development,production,testing}
    mkdir -p docs/{api,architecture,deployment}
    mkdir -p scripts/{build,deploy,test}
    mkdir -p monitoring/{prometheus,grafana}
    
    log_success "Project directories created"
}

# Set up a basic development database
setup_database() {
    log_info "Setting up development database..."
    
    # Just create an empty SQLite database for now
    mkdir -p data
    touch data/governor.db
    
    log_success "Development database initialized"
}

# Create a placeholder for AI models
download_models() {
    log_info "Setting up model directory..."
    
    mkdir -p models
    
    # Create a README explaining how to get models
    cat > models/README.md << 'EOF'
# AI Models Directory

This directory is where you put the AI models used by the Universal AI Governor.

## Required Models

For the AI policy synthesis feature, you'll need:
- A policy generation model (GGUF format recommended)
- A threat detection model (ONNX format)

## Where to get models

You can download compatible models from:
- Hugging Face (https://huggingface.co/models)
- Ollama model library (https://ollama.ai/library)

## Example setup

```bash
# Download a small model for testing
curl -L "https://huggingface.co/microsoft/DialoGPT-medium/resolve/main/pytorch_model.bin" -o policy_generator.bin

# Or use Ollama
ollama pull llama2:7b
```

## Security Note

Always verify model checksums and only use models from trusted sources.
EOF
    
    log_success "Model directory configured"
}

# Set up Git hooks for development
setup_git_hooks() {
    if [ ! -d ".git" ]; then
        log_warning "Not a Git repository. Skipping Git hooks setup."
        return
    fi

    log_info "Setting up Git hooks..."
    
    # Pre-commit hook to run basic checks
    cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Pre-commit hook for Universal AI Governor
# This runs some basic checks before allowing commits

set -e

echo "Running pre-commit checks..."

# Check code formatting
echo "Checking code formatting..."
if ! cargo fmt --all -- --check; then
    echo "Code formatting issues found. Run 'cargo fmt' to fix."
    exit 1
fi

# Run clippy
echo "Running clippy..."
if ! cargo clippy --all-targets --all-features -- -D warnings; then
    echo "Clippy found issues. Please fix them before committing."
    exit 1
fi

# Run a quick test to make sure nothing is obviously broken
echo "Running quick tests..."
if ! cargo test --lib; then
    echo "Tests failed. Please fix them before committing."
    exit 1
fi

echo "Pre-commit checks passed!"
EOF

    chmod +x .git/hooks/pre-commit
    
    log_success "Git hooks configured"
}

# Generate some development certificates
generate_dev_certs() {
    log_info "Generating development certificates..."
    
    mkdir -p certs
    
    # Generate a self-signed certificate for local development
    # This is obviously not for production use
    openssl req -x509 -newkey rsa:4096 -keyout certs/dev-key.pem -out certs/dev-cert.pem -days 365 -nodes \
        -subj "/C=US/ST=Development/L=Local/O=Universal AI Governor/CN=localhost" 2>/dev/null || {
        log_warning "Failed to generate certificates (openssl might not be available)"
        return
    }
    
    log_success "Development certificates generated"
}

# Create environment configuration
setup_environment() {
    log_info "Setting up environment configuration..."
    
    # Create an example environment file
    cat > .env.example << 'EOF'
# Universal AI Governor - Environment Variables
# Copy this file to .env and customize for your environment

# Database
DATABASE_URL=sqlite://./data/governor.db
REDIS_URL=redis://localhost:6379

# Security (change these in production!)
JWT_SECRET=development-secret-change-in-production
ENCRYPTION_KEY=dev-encryption-key-32-characters-long

# Hardware Security (disable for development)
TPM_ENABLED=false
HSM_ENABLED=false
SECURE_ENCLAVE_ENABLED=false

# AI Features
AI_SYNTHESIS_ENABLED=false
LLM_MODEL_PATH=./models/policy_generator.gguf

# Logging
RUST_LOG=info
RUST_BACKTRACE=1

# Development flags
DEVELOPMENT_MODE=true
DEBUG_LOGGING=true
EOF

    if [ ! -f ".env" ]; then
        cp .env.example .env
        log_info "Created .env file from template"
    fi
    
    log_success "Environment configuration ready"
}

# Make sure everything actually works
verify_installation() {
    log_info "Verifying installation..."
    
    # Check that Rust is working
    if ! command_exists rustc; then
        log_error "Rust installation failed"
        exit 1
    fi
    
    if ! command_exists cargo; then
        log_error "Cargo installation failed"
        exit 1
    fi
    
    # Try to build the project
    log_info "Testing build... (this might take a while the first time)"
    if cargo check --all-features; then
        log_success "Build check passed"
    else
        log_error "Build check failed - you might need to install additional dependencies"
        exit 1
    fi
    
    log_success "Installation verified successfully"
}

# Show what to do next
print_next_steps() {
    echo -e "${GREEN}"
    echo "+================================================================+"
    echo "|                                                                |"
    echo "|                    SETUP COMPLETE!                            |"
    echo "|                                                                |"
    echo "|  Next steps:                                                   |"
    echo "|                                                                |"
    echo "|  1. Build the project:                                         |"
    echo "|     cargo build --release --all-features                      |"
    echo "|                                                                |"
    echo "|  2. Run tests:                                                 |"
    echo "|     cargo test --all-features                                  |"
    echo "|                                                                |"
    echo "|  3. Start development server:                                  |"
    echo "|     cargo run -- --config config/default.toml                 |"
    echo "|                                                                |"
    echo "|  4. Read the docs:                                             |"
    echo "|     cargo doc --open --all-features                           |"
    echo "|                                                                |"
    echo "+================================================================+"
    echo -e "${NC}"
}

# Main setup function
main() {
    print_banner
    
    log_info "Starting Universal AI Governor setup..."
    
    # Do all the setup steps
    install_rust
    install_system_deps
    install_rust_tools
    create_directories
    setup_database
    download_models
    setup_git_hooks
    generate_dev_certs
    setup_environment
    verify_installation
    
    print_next_steps
    
    log_success "Setup completed successfully!"
}

# Run the main function
main "$@"

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Detect operating system
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt-get; then
            echo "ubuntu"
        elif command_exists yum; then
            echo "centos"
        elif command_exists pacman; then
            echo "arch"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

# Install Rust
install_rust() {
    if command_exists rustc; then
        log_info "Rust is already installed ($(rustc --version))"
        return
    fi

    log_info "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
    log_success "Rust installed successfully"
}

# Install system dependencies
install_system_deps() {
    local os=$(detect_os)
    log_info "Installing system dependencies for $os..."

    case $os in
        ubuntu)
            sudo apt-get update
            sudo apt-get install -y \
                build-essential \
                pkg-config \
                libssl-dev \
                libtss2-dev \
                tpm2-tools \
                libopencv-dev \
                libclang-dev \
                curl \
                git
            ;;
        centos)
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y \
                pkg-config \
                openssl-devel \
                tpm2-tss-devel \
                tpm2-tools \
                opencv-devel \
                clang-devel \
                curl \
                git
            ;;
        arch)
            sudo pacman -S --noconfirm \
                base-devel \
                pkg-config \
                openssl \
                tpm2-tss \
                tpm2-tools \
                opencv \
                clang \
                curl \
                git
            ;;
        macos)
            if ! command_exists brew; then
                log_info "Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install \
                pkg-config \
                openssl \
                tpm2-tools \
                opencv \
                llvm
            ;;
        *)
            log_warning "Unknown operating system. Please install dependencies manually."
            log_info "Required packages: build-essential, pkg-config, libssl-dev, libtss2-dev, tpm2-tools, libopencv-dev"
            ;;
    esac

    log_success "System dependencies installed"
}

# Install Rust tools
install_rust_tools() {
    log_info "Installing Rust development tools..."
    
    # Essential tools
    cargo install cargo-watch cargo-edit cargo-audit cargo-deny
    
    # Testing and coverage tools
    cargo install cargo-tarpaulin cargo-nextest
    
    # Performance tools
    cargo install cargo-criterion flamegraph
    
    # Documentation tools
    cargo install mdbook mdbook-mermaid
    
    log_success "Rust tools installed"
}

# Create directories
create_directories() {
    log_info "Creating project directories..."
    
    mkdir -p {data,logs,models,keys,certs,tmp}
    mkdir -p config/{development,production,testing}
    mkdir -p docs/{api,architecture,deployment}
    mkdir -p scripts/{build,deploy,test}
    mkdir -p monitoring/{prometheus,grafana}
    
    log_success "Project directories created"
}

# Setup development database
setup_database() {
    log_info "Setting up development database..."
    
    # Create SQLite database for development
    mkdir -p data
    touch data/governor.db
    
    log_success "Development database initialized"
}

# Download example models (if available)
download_models() {
    log_info "Setting up model directory..."
    
    mkdir -p models
    
    # Create placeholder for model files
    cat > models/README.md << EOF
# AI Models Directory

This directory contains AI models used by the Universal AI Governor.

## Policy Generation Models

Place your LLM models here for AI-driven policy synthesis:
- \`policy_generator.gguf\` - Main policy generation model
- \`threat_detector.onnx\` - Threat detection model
- \`behavioral_analyzer.bin\` - Behavioral analysis model

## Supported Formats

- GGUF (llama.cpp compatible)
- ONNX (Open Neural Network Exchange)
- SafeTensors
- PyTorch (.bin, .pt)

## Download Instructions

1. Download models from Hugging Face or other sources
2. Place them in this directory
3. Update configuration files to point to the correct model paths
4. Ensure models are compatible with the inference engines

## Security Note

Models should be verified for integrity and authenticity before use.
Use checksums and digital signatures when available.
EOF
    
    log_success "Model directory configured"
}

# Setup Git hooks
setup_git_hooks() {
    if [ ! -d ".git" ]; then
        log_warning "Not a Git repository. Skipping Git hooks setup."
        return
    fi

    log_info "Setting up Git hooks..."
    
    # Pre-commit hook
    cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Pre-commit hook for Universal AI Governor

set -e

echo "Running pre-commit checks..."

# Check formatting
echo "Checking code formatting..."
cargo fmt --all -- --check

# Run clippy
echo "Running clippy..."
cargo clippy --all-targets --all-features -- -D warnings

# Run tests
echo "Running tests..."
cargo test --all-features

echo "Pre-commit checks passed!"
EOF

    chmod +x .git/hooks/pre-commit
    
    log_success "Git hooks configured"
}

# Generate development certificates
generate_dev_certs() {
    log_info "Generating development certificates..."
    
    mkdir -p certs
    
    # Generate self-signed certificate for development
    openssl req -x509 -newkey rsa:4096 -keyout certs/dev-key.pem -out certs/dev-cert.pem -days 365 -nodes -subj "/C=US/ST=Development/L=Local/O=Universal AI Governor/CN=localhost"
    
    log_success "Development certificates generated"
}

# Setup environment file
setup_environment() {
    log_info "Setting up environment configuration..."
    
    cat > .env.example << 'EOF'
# Universal AI Governor - Environment Variables
# Copy this file to .env and customize for your environment

# Database
DATABASE_URL=sqlite://./data/governor.db
REDIS_URL=redis://localhost:6379

# Security
JWT_SECRET=development-secret-change-in-production
ENCRYPTION_KEY=dev-encryption-key-32-characters

# Hardware
TPM_ENABLED=false
HSM_ENABLED=false
SECURE_ENCLAVE_ENABLED=false

# AI Synthesis
AI_SYNTHESIS_ENABLED=false
LLM_MODEL_PATH=./models/policy_generator.gguf

# Logging
RUST_LOG=info
RUST_BACKTRACE=1

# Development
DEVELOPMENT_MODE=true
DEBUG_LOGGING=true
EOF

    if [ ! -f ".env" ]; then
        cp .env.example .env
        log_info "Created .env file from template"
    fi
    
    log_success "Environment configuration ready"
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    # Check Rust
    if ! command_exists rustc; then
        log_error "Rust installation failed"
        exit 1
    fi
    
    # Check cargo
    if ! command_exists cargo; then
        log_error "Cargo installation failed"
        exit 1
    fi
    
    # Try to build the project
    log_info "Testing build..."
    if cargo check --all-features; then
        log_success "Build check passed"
    else
        log_error "Build check failed"
        exit 1
    fi
    
    log_success "Installation verified successfully"
}

# Print next steps
print_next_steps() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                  ║"
    echo "║                    🎉 SETUP COMPLETE! 🎉                        ║"
    echo "║                                                                  ║"
    echo "║  Next steps:                                                     ║"
    echo "║                                                                  ║"
    echo "║  1. Build the project:                                           ║"
    echo "║     cargo build --release --all-features                        ║"
    echo "║                                                                  ║"
    echo "║  2. Run tests:                                                   ║"
    echo "║     cargo test --all-features                                    ║"
    echo "║                                                                  ║"
    echo "║  3. Start the development server:                                ║"
    echo "║     cargo run -- --config config/default.toml                   ║"
    echo "║                                                                  ║"
    echo "║  4. View documentation:                                          ║"
    echo "║     cargo doc --open --all-features                             ║"
    echo "║                                                                  ║"
    echo "║  5. Run with Docker:                                             ║"
    echo "║     docker-compose up -d                                         ║"
    echo "║                                                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Main setup function
main() {
    print_banner
    
    log_info "Starting Universal AI Governor setup..."
    
    install_rust
    install_system_deps
    install_rust_tools
    create_directories
    setup_database
    download_models
    setup_git_hooks
    generate_dev_certs
    setup_environment
    verify_installation
    
    print_next_steps
    
    log_success "Setup completed successfully!"
}

# Run main function
main "$@"
