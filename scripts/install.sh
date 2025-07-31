#!/bin/bash

# Universal AI Governor Installation Script
# Supports: Linux, macOS, Windows (via WSL/Git Bash)

set -e

# Configuration
REPO_URL="https://github.com/your-org/universal-ai-governor"
BINARY_NAME="ai-governor"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/ai-governor"
DATA_DIR="/var/lib/ai-governor"
LOG_DIR="/var/log/ai-governor"
SERVICE_NAME="ai-governor"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    case $OS in
        linux*)
            OS="linux"
            ;;
        darwin*)
            OS="darwin"
            ;;
        cygwin*|mingw*|msys*)
            OS="windows"
            ;;
        *)
            log_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac
    
    case $ARCH in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        arm64|aarch64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="arm"
            ;;
        i386|i686)
            ARCH="386"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    
    PLATFORM="${OS}_${ARCH}"
    log_info "Detected platform: $PLATFORM"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        IS_ROOT=true
        log_info "Running as root"
    else
        IS_ROOT=false
        log_warning "Not running as root. Some features may require sudo."
    fi
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check for curl or wget
    if command -v curl >/dev/null 2>&1; then
        DOWNLOADER="curl -L"
    elif command -v wget >/dev/null 2>&1; then
        DOWNLOADER="wget -O-"
    else
        log_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi
    
    # Check for tar
    if ! command -v tar >/dev/null 2>&1; then
        log_error "tar not found. Please install tar."
        exit 1
    fi
    
    # Check for systemctl (Linux only)
    if [[ "$OS" == "linux" ]] && command -v systemctl >/dev/null 2>&1; then
        HAS_SYSTEMD=true
    else
        HAS_SYSTEMD=false
    fi
    
    log_success "Dependencies check completed"
}

# Get latest release version
get_latest_version() {
    log_info "Getting latest release version..."
    
    if command -v curl >/dev/null 2>&1; then
        VERSION=$(curl -s "https://api.github.com/repos/your-org/universal-ai-governor/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    elif command -v wget >/dev/null 2>&1; then
        VERSION=$(wget -qO- "https://api.github.com/repos/your-org/universal-ai-governor/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    fi
    
    if [[ -z "$VERSION" ]]; then
        log_warning "Could not determine latest version. Using v1.0.0"
        VERSION="v1.0.0"
    fi
    
    log_info "Latest version: $VERSION"
}

# Download and install binary
install_binary() {
    log_info "Downloading Universal AI Governor $VERSION for $PLATFORM..."
    
    DOWNLOAD_URL="https://github.com/your-org/universal-ai-governor/releases/download/${VERSION}/${BINARY_NAME}-${PLATFORM}.tar.gz"
    TEMP_DIR=$(mktemp -d)
    
    cd "$TEMP_DIR"
    
    if [[ "$DOWNLOADER" == "curl -L" ]]; then
        curl -L "$DOWNLOAD_URL" | tar xz
    else
        wget -O- "$DOWNLOAD_URL" | tar xz
    fi
    
    # Make binary executable
    chmod +x "$BINARY_NAME"
    
    # Install binary
    if [[ "$IS_ROOT" == true ]]; then
        mv "$BINARY_NAME" "$INSTALL_DIR/"
        log_success "Binary installed to $INSTALL_DIR/$BINARY_NAME"
    else
        # Install to user's local bin
        mkdir -p "$HOME/.local/bin"
        mv "$BINARY_NAME" "$HOME/.local/bin/"
        INSTALL_DIR="$HOME/.local/bin"
        log_success "Binary installed to $HOME/.local/bin/$BINARY_NAME"
        log_warning "Make sure $HOME/.local/bin is in your PATH"
    fi
    
    # Cleanup
    cd - >/dev/null
    rm -rf "$TEMP_DIR"
}

# Create directories
create_directories() {
    log_info "Creating directories..."
    
    if [[ "$IS_ROOT" == true ]]; then
        mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
        chown -R nobody:nobody "$DATA_DIR" "$LOG_DIR" 2>/dev/null || true
    else
        CONFIG_DIR="$HOME/.config/ai-governor"
        DATA_DIR="$HOME/.local/share/ai-governor"
        LOG_DIR="$HOME/.local/share/ai-governor/logs"
        mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
    fi
    
    log_success "Directories created"
}

# Install configuration files
install_config() {
    log_info "Installing configuration files..."
    
    # Download default config
    CONFIG_URL="https://raw.githubusercontent.com/your-org/universal-ai-governor/main/configs/config.yaml"
    
    if [[ "$DOWNLOADER" == "curl -L" ]]; then
        curl -L "$CONFIG_URL" -o "$CONFIG_DIR/config.yaml"
    else
        wget -O "$CONFIG_DIR/config.yaml" "$CONFIG_URL"
    fi
    
    # Download default policies
    POLICY_URL="https://raw.githubusercontent.com/your-org/universal-ai-governor/main/policies/base.rego"
    mkdir -p "$CONFIG_DIR/policies"
    
    if [[ "$DOWNLOADER" == "curl -L" ]]; then
        curl -L "$POLICY_URL" -o "$CONFIG_DIR/policies/base.rego"
    else
        wget -O "$CONFIG_DIR/policies/base.rego" "$POLICY_URL"
    fi
    
    log_success "Configuration files installed"
}

# Create systemd service (Linux only)
create_systemd_service() {
    if [[ "$OS" != "linux" ]] || [[ "$HAS_SYSTEMD" != true ]] || [[ "$IS_ROOT" != true ]]; then
        return
    fi
    
    log_info "Creating systemd service..."
    
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=Universal AI Governor
Documentation=https://github.com/your-org/universal-ai-governor
After=network.target
Wants=network.target

[Service]
Type=simple
User=nobody
Group=nobody
ExecStart=${INSTALL_DIR}/${BINARY_NAME} --config ${CONFIG_DIR}/config.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}
KillMode=mixed
KillSignal=SIGTERM

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR} ${LOG_DIR}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    log_success "Systemd service created"
}

# Create launchd service (macOS only)
create_launchd_service() {
    if [[ "$OS" != "darwin" ]] || [[ "$IS_ROOT" != true ]]; then
        return
    fi
    
    log_info "Creating launchd service..."
    
    cat > "/Library/LaunchDaemons/com.aigovernor.${SERVICE_NAME}.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.aigovernor.${SERVICE_NAME}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/${BINARY_NAME}</string>
        <string>--config</string>
        <string>${CONFIG_DIR}/config.yaml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/stderr.log</string>
    <key>WorkingDirectory</key>
    <string>${DATA_DIR}</string>
</dict>
</plist>
EOF
    
    launchctl load "/Library/LaunchDaemons/com.aigovernor.${SERVICE_NAME}.plist"
    log_success "Launchd service created"
}

# Install package manager integration
install_package_manager() {
    case "$OS" in
        linux)
            if command -v apt-get >/dev/null 2>&1; then
                install_deb_package
            elif command -v yum >/dev/null 2>&1; then
                install_rpm_package
            elif command -v pacman >/dev/null 2>&1; then
                install_arch_package
            fi
            ;;
        darwin)
            install_homebrew_formula
            ;;
    esac
}

# Post-installation setup
post_install() {
    log_info "Running post-installation setup..."
    
    # Verify installation
    if command -v "$BINARY_NAME" >/dev/null 2>&1; then
        VERSION_OUTPUT=$("$BINARY_NAME" --version 2>/dev/null || echo "Version check failed")
        log_success "Installation verified: $VERSION_OUTPUT"
    else
        log_warning "Binary not found in PATH. You may need to add $INSTALL_DIR to your PATH."
    fi
    
    # Create sample data
    if [[ -d "$DATA_DIR" ]]; then
        echo '{"system": {"maintenance_mode": false}, "users": {}}' > "$DATA_DIR/data.json"
    fi
    
    log_success "Post-installation setup completed"
}

# Print usage information
print_usage() {
    cat << EOF

Universal AI Governor has been installed successfully!

Configuration:
  Config file: $CONFIG_DIR/config.yaml
  Data directory: $DATA_DIR
  Log directory: $LOG_DIR

Usage:
  Start the service:
    $BINARY_NAME --config $CONFIG_DIR/config.yaml

  Check status:
    curl http://localhost:8080/health

  View logs:
    tail -f $LOG_DIR/governor.log

EOF

    if [[ "$HAS_SYSTEMD" == true ]] && [[ "$IS_ROOT" == true ]]; then
        cat << EOF
Systemd commands:
  Start service:    sudo systemctl start $SERVICE_NAME
  Stop service:     sudo systemctl stop $SERVICE_NAME
  Enable on boot:   sudo systemctl enable $SERVICE_NAME
  View logs:        sudo journalctl -u $SERVICE_NAME -f

EOF
    fi

    if [[ "$OS" == "darwin" ]] && [[ "$IS_ROOT" == true ]]; then
        cat << EOF
Launchd commands:
  Start service:    sudo launchctl load /Library/LaunchDaemons/com.aigovernor.$SERVICE_NAME.plist
  Stop service:     sudo launchctl unload /Library/LaunchDaemons/com.aigovernor.$SERVICE_NAME.plist

EOF
    fi

    cat << EOF
Documentation: https://github.com/your-org/universal-ai-governor/docs
Support: https://github.com/your-org/universal-ai-governor/issues

EOF
}

# Main installation function
main() {
    log_info "Starting Universal AI Governor installation..."
    
    detect_platform
    check_root
    check_dependencies
    get_latest_version
    install_binary
    create_directories
    install_config
    create_systemd_service
    create_launchd_service
    post_install
    
    log_success "Installation completed successfully!"
    print_usage
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Universal AI Governor Installation Script"
        echo "Usage: $0 [--help|--uninstall]"
        echo ""
        echo "Options:"
        echo "  --help      Show this help message"
        echo "  --uninstall Remove Universal AI Governor"
        exit 0
        ;;
    --uninstall)
        log_info "Uninstalling Universal AI Governor..."
        
        # Stop and disable services
        if [[ "$HAS_SYSTEMD" == true ]] && [[ "$IS_ROOT" == true ]]; then
            systemctl stop "$SERVICE_NAME" 2>/dev/null || true
            systemctl disable "$SERVICE_NAME" 2>/dev/null || true
            rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
            systemctl daemon-reload
        fi
        
        if [[ "$OS" == "darwin" ]] && [[ "$IS_ROOT" == true ]]; then
            launchctl unload "/Library/LaunchDaemons/com.aigovernor.${SERVICE_NAME}.plist" 2>/dev/null || true
            rm -f "/Library/LaunchDaemons/com.aigovernor.${SERVICE_NAME}.plist"
        fi
        
        # Remove binary
        rm -f "$INSTALL_DIR/$BINARY_NAME"
        rm -f "$HOME/.local/bin/$BINARY_NAME"
        
        # Remove directories (ask for confirmation)
        read -p "Remove configuration and data directories? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
            rm -rf "$HOME/.config/ai-governor" "$HOME/.local/share/ai-governor"
        fi
        
        log_success "Uninstallation completed"
        exit 0
        ;;
    *)
        main
        ;;
esac
