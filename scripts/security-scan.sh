#!/bin/bash

# Universal AI Governor Security Scanning Script
# Performs comprehensive security analysis including SAST, DAST, and dependency scanning

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SCAN_RESULTS_DIR="$PROJECT_ROOT/security-reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() {
    echo -e "${BLUE}[SECURITY-SCAN]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SECURITY-SCAN]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[SECURITY-SCAN]${NC} $1"
}

log_error() {
    echo -e "${RED}[SECURITY-SCAN]${NC} $1"
}

# Create results directory
mkdir -p "$SCAN_RESULTS_DIR"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install security tools if not present
install_security_tools() {
    log_info "Checking and installing security tools..."
    
    # Install gosec for Go security analysis
    if ! command_exists gosec; then
        log_info "Installing gosec..."
        go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
    fi
    
    # Install nancy for dependency vulnerability scanning
    if ! command_exists nancy; then
        log_info "Installing nancy..."
        go install github.com/sonatypecommunity/nancy@latest
    fi
    
    # Install trivy for container scanning
    if ! command_exists trivy; then
        log_info "Installing trivy..."
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            brew install trivy
        fi
    fi
    
    # Install semgrep for static analysis
    if ! command_exists semgrep; then
        log_info "Installing semgrep..."
        pip3 install semgrep
    fi
    
    log_success "Security tools installation completed"
}

# Static Application Security Testing (SAST)
run_sast_scan() {
    log_info "Running Static Application Security Testing (SAST)..."
    
    cd "$PROJECT_ROOT"
    
    # Run gosec for Go-specific security issues
    log_info "Running gosec scan..."
    gosec -fmt json -out "$SCAN_RESULTS_DIR/gosec-report-$TIMESTAMP.json" ./... || true
    gosec -fmt text -out "$SCAN_RESULTS_DIR/gosec-report-$TIMESTAMP.txt" ./... || true
    
    # Run semgrep for broader security patterns
    if command_exists semgrep; then
        log_info "Running semgrep scan..."
        semgrep --config=auto --json --output="$SCAN_RESULTS_DIR/semgrep-report-$TIMESTAMP.json" . || true
        semgrep --config=auto --output="$SCAN_RESULTS_DIR/semgrep-report-$TIMESTAMP.txt" . || true
    fi
    
    log_success "SAST scan completed"
}

# Dependency vulnerability scanning
run_dependency_scan() {
    log_info "Running dependency vulnerability scan..."
    
    cd "$PROJECT_ROOT"
    
    # Generate dependency list
    go list -json -m all > "$SCAN_RESULTS_DIR/go-modules-$TIMESTAMP.json"
    
    # Run nancy for Go dependencies
    if command_exists nancy; then
        log_info "Running nancy dependency scan..."
        go list -json -m all | nancy sleuth --output-format=json > "$SCAN_RESULTS_DIR/nancy-report-$TIMESTAMP.json" || true
        go list -json -m all | nancy sleuth > "$SCAN_RESULTS_DIR/nancy-report-$TIMESTAMP.txt" || true
    fi
    
    # Check for known vulnerable packages
    log_info "Checking for known vulnerable Go packages..."
    go list -json -m all | jq -r '.Path' | while read -r pkg; do
        if [[ "$pkg" =~ (github\.com/.*/(jwt|crypto|auth).*)|(.*vulnerable.*) ]]; then
            echo "Potentially vulnerable package: $pkg" >> "$SCAN_RESULTS_DIR/vulnerable-packages-$TIMESTAMP.txt"
        fi
    done
    
    log_success "Dependency scan completed"
}

# Container security scanning
run_container_scan() {
    log_info "Running container security scan..."
    
    cd "$PROJECT_ROOT"
    
    # Build container image for scanning
    if [ -f "Dockerfile" ]; then
        log_info "Building container image for security scan..."
        docker build -t ai-governor-security-scan:latest . || {
            log_warning "Failed to build container image, skipping container scan"
            return
        }
        
        # Run trivy container scan
        if command_exists trivy; then
            log_info "Running trivy container scan..."
            trivy image --format json --output "$SCAN_RESULTS_DIR/trivy-container-$TIMESTAMP.json" ai-governor-security-scan:latest || true
            trivy image --format table --output "$SCAN_RESULTS_DIR/trivy-container-$TIMESTAMP.txt" ai-governor-security-scan:latest || true
        fi
        
        # Clean up scan image
        docker rmi ai-governor-security-scan:latest || true
    else
        log_warning "No Dockerfile found, skipping container scan"
    fi
    
    log_success "Container scan completed"
}

# Secret scanning
run_secret_scan() {
    log_info "Running secret scanning..."
    
    cd "$PROJECT_ROOT"
    
    # Check for common secret patterns
    log_info "Scanning for hardcoded secrets..."
    
    # Define secret patterns
    declare -A secret_patterns=(
        ["API_KEY"]="(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}['\"]?"
        ["PASSWORD"]="(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?"
        ["TOKEN"]="(?i)(token|auth[_-]?token)\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}['\"]?"
        ["SECRET"]="(?i)(secret|secret[_-]?key)\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}['\"]?"
        ["PRIVATE_KEY"]="-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"
        ["AWS_KEY"]="AKIA[0-9A-Z]{16}"
        ["JWT"]="eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"
    )
    
    secret_report="$SCAN_RESULTS_DIR/secrets-scan-$TIMESTAMP.txt"
    echo "Secret Scanning Report - $(date)" > "$secret_report"
    echo "=======================================" >> "$secret_report"
    
    for pattern_name in "${!secret_patterns[@]}"; do
        pattern="${secret_patterns[$pattern_name]}"
        echo "Scanning for: $pattern_name" >> "$secret_report"
        
        # Scan all files except common exclusions
        find . -type f \
            -not -path "./.git/*" \
            -not -path "./vendor/*" \
            -not -path "./node_modules/*" \
            -not -path "./build/*" \
            -not -path "./dist/*" \
            -not -path "./$SCAN_RESULTS_DIR/*" \
            -exec grep -l -E "$pattern" {} \; 2>/dev/null >> "$secret_report" || true
        
        echo "" >> "$secret_report"
    done
    
    # Use truffleHog if available
    if command_exists trufflehog; then
        log_info "Running truffleHog secret scan..."
        trufflehog filesystem . --json > "$SCAN_RESULTS_DIR/trufflehog-$TIMESTAMP.json" || true
    fi
    
    log_success "Secret scan completed"
}

# Configuration security analysis
run_config_scan() {
    log_info "Running configuration security analysis..."
    
    cd "$PROJECT_ROOT"
    
    config_report="$SCAN_RESULTS_DIR/config-security-$TIMESTAMP.txt"
    echo "Configuration Security Analysis - $(date)" > "$config_report"
    echo "=============================================" >> "$config_report"
    
    # Check for insecure configurations
    log_info "Analyzing configuration files..."
    
    # Check YAML/JSON config files
    find . -name "*.yaml" -o -name "*.yml" -o -name "*.json" | while read -r file; do
        echo "Analyzing: $file" >> "$config_report"
        
        # Check for insecure settings
        if grep -i "debug.*true\|log.*debug\|insecure.*true\|ssl.*false\|tls.*false" "$file" >/dev/null 2>&1; then
            echo "  WARNING: Potentially insecure configuration found" >> "$config_report"
            grep -n -i "debug.*true\|log.*debug\|insecure.*true\|ssl.*false\|tls.*false" "$file" >> "$config_report" || true
        fi
        
        echo "" >> "$config_report"
    done
    
    # Check Docker configurations
    if [ -f "Dockerfile" ]; then
        echo "Analyzing Dockerfile security..." >> "$config_report"
        
        # Check for security issues in Dockerfile
        if grep -i "USER root\|--privileged\|--cap-add" Dockerfile >/dev/null 2>&1; then
            echo "  WARNING: Potentially insecure Docker configuration" >> "$config_report"
            grep -n -i "USER root\|--privileged\|--cap-add" Dockerfile >> "$config_report" || true
        fi
    fi
    
    log_success "Configuration scan completed"
}

# Generate security report summary
generate_summary_report() {
    log_info "Generating security report summary..."
    
    summary_report="$SCAN_RESULTS_DIR/security-summary-$TIMESTAMP.txt"
    
    cat > "$summary_report" << EOF
Universal AI Governor Security Scan Summary
==========================================
Scan Date: $(date)
Scan ID: $TIMESTAMP

SCAN RESULTS:
EOF
    
    # Count issues from different scans
    if [ -f "$SCAN_RESULTS_DIR/gosec-report-$TIMESTAMP.json" ]; then
        gosec_issues=$(jq '.Stats.found // 0' "$SCAN_RESULTS_DIR/gosec-report-$TIMESTAMP.json" 2>/dev/null || echo "0")
        echo "GoSec Issues Found: $gosec_issues" >> "$summary_report"
    fi
    
    if [ -f "$SCAN_RESULTS_DIR/nancy-report-$TIMESTAMP.json" ]; then
        nancy_vulns=$(jq '.vulnerable // [] | length' "$SCAN_RESULTS_DIR/nancy-report-$TIMESTAMP.json" 2>/dev/null || echo "0")
        echo "Dependency Vulnerabilities: $nancy_vulns" >> "$summary_report"
    fi
    
    if [ -f "$SCAN_RESULTS_DIR/trivy-container-$TIMESTAMP.json" ]; then
        trivy_high=$(jq '.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH") | .VulnerabilityID' "$SCAN_RESULTS_DIR/trivy-container-$TIMESTAMP.json" 2>/dev/null | wc -l || echo "0")
        trivy_critical=$(jq '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL") | .VulnerabilityID' "$SCAN_RESULTS_DIR/trivy-container-$TIMESTAMP.json" 2>/dev/null | wc -l || echo "0")
        echo "Container High Severity Issues: $trivy_high" >> "$summary_report"
        echo "Container Critical Issues: $trivy_critical" >> "$summary_report"
    fi
    
    cat >> "$summary_report" << EOF

RECOMMENDATIONS:
1. Review all HIGH and CRITICAL severity issues immediately
2. Update vulnerable dependencies to latest secure versions
3. Remove or secure any hardcoded secrets found
4. Enable security headers and HTTPS in production
5. Implement proper input validation and sanitization
6. Regular security scans should be integrated into CI/CD pipeline

REPORT FILES:
EOF
    
    # List all generated report files
    ls -la "$SCAN_RESULTS_DIR"/*-$TIMESTAMP.* >> "$summary_report" 2>/dev/null || true
    
    log_success "Security summary report generated: $summary_report"
}

# Main execution
main() {
    log_info "Starting comprehensive security scan..."
    log_info "Results will be saved to: $SCAN_RESULTS_DIR"
    
    # Install required tools
    install_security_tools
    
    # Run all security scans
    run_sast_scan
    run_dependency_scan
    run_container_scan
    run_secret_scan
    run_config_scan
    
    # Generate summary
    generate_summary_report
    
    log_success "Security scan completed successfully!"
    log_info "Review the reports in: $SCAN_RESULTS_DIR"
    
    # Display summary
    if [ -f "$SCAN_RESULTS_DIR/security-summary-$TIMESTAMP.txt" ]; then
        echo ""
        log_info "Security Scan Summary:"
        cat "$SCAN_RESULTS_DIR/security-summary-$TIMESTAMP.txt"
    fi
}

# Run main function
main "$@"
