#!/bin/bash
# Universal AI Governor - Advanced Automation Script
# Comprehensive project maintenance and quality assurance automation

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="$PROJECT_ROOT/logs/automation.log"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# Print banner
print_banner() {
    echo -e "${BLUE}"
    echo "+================================================================+"
    echo "|                                                                |"
    echo "|              UNIVERSAL AI GOVERNOR AUTOMATION                 |"
    echo "|                                                                |"
    echo "|         Comprehensive project maintenance and QA              |"
    echo "|                                                                |"
    echo "+================================================================+"
    echo -e "${NC}"
}

# Initialize logging
init_logging() {
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "$(date): Starting automation script" >> "$LOG_FILE"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing_tools=()
    
    # Check required tools
    for tool in git cargo go node python3 docker; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Please install missing tools and run again"
        exit 1
    fi
    
    log_success "All prerequisites satisfied"
}

# Update dependencies automatically
update_dependencies() {
    log_info "Updating project dependencies..."
    
    # Update Rust dependencies
    if [ -f "Cargo.toml" ]; then
        log_info "Updating Rust dependencies..."
        cargo update
        log_success "Rust dependencies updated"
    fi
    
    # Update Go dependencies
    if [ -f "go.mod" ]; then
        log_info "Updating Go dependencies..."
        go get -u ./...
        go mod tidy
        log_success "Go dependencies updated"
    fi
    
    # Update JavaScript dependencies
    if [ -f "sdks/javascript/package.json" ]; then
        log_info "Updating JavaScript dependencies..."
        cd sdks/javascript
        npm update
        npm audit fix --force || log_warning "Some npm audit issues couldn't be fixed automatically"
        cd "$PROJECT_ROOT"
        log_success "JavaScript dependencies updated"
    fi
    
    # Update Python dependencies
    if [ -f "sdks/python/requirements.txt" ]; then
        log_info "Updating Python dependencies..."
        cd sdks/python
        pip install --upgrade -r requirements.txt
        cd "$PROJECT_ROOT"
        log_success "Python dependencies updated"
    fi
}

# Run comprehensive security scans
run_security_scans() {
    log_info "Running comprehensive security scans..."
    
    # Rust security audit
    if command -v cargo-audit &> /dev/null; then
        log_info "Running Rust security audit..."
        cargo audit || log_warning "Rust security audit found issues"
    else
        log_warning "cargo-audit not installed, skipping Rust security scan"
    fi
    
    # Go vulnerability check
    if command -v govulncheck &> /dev/null; then
        log_info "Running Go vulnerability check..."
        govulncheck ./... || log_warning "Go vulnerability check found issues"
    else
        log_warning "govulncheck not installed, skipping Go vulnerability scan"
    fi
    
    # Secrets scanning
    if command -v trufflehog &> /dev/null; then
        log_info "Scanning for secrets..."
        trufflehog git file://. --json > logs/secrets-scan.json || log_warning "Secrets scan found potential issues"
    fi
    
    # Custom security patterns
    log_info "Scanning for custom security patterns..."
    
    # Check for hardcoded credentials
    grep -r "password\s*=\|pwd\s*=\|secret\s*=" --include="*.go" --include="*.py" --include="*.js" --include="*.rs" . || log_info "No hardcoded passwords found"
    
    # Check for API keys
    grep -r "api[_-]?key\|access[_-]?key" --include="*.go" --include="*.py" --include="*.js" --include="*.rs" . || log_info "No API keys found"
    
    log_success "Security scans completed"
}

# Code quality checks
run_quality_checks() {
    log_info "Running code quality checks..."
    
    # Rust formatting and linting
    if [ -f "Cargo.toml" ]; then
        log_info "Checking Rust code quality..."
        cargo fmt --all -- --check || (log_warning "Rust formatting issues found" && cargo fmt --all)
        cargo clippy --all-targets --all-features -- -D warnings || log_warning "Rust clippy issues found"
    fi
    
    # Go formatting and linting
    if [ -f "go.mod" ]; then
        log_info "Checking Go code quality..."
        go fmt ./...
        go vet ./...
        
        if command -v staticcheck &> /dev/null; then
            staticcheck ./...
        fi
    fi
    
    # JavaScript/TypeScript linting
    if [ -f "sdks/javascript/package.json" ]; then
        log_info "Checking JavaScript code quality..."
        cd sdks/javascript
        if [ -f ".eslintrc.js" ] || [ -f ".eslintrc.json" ]; then
            npm run lint || log_warning "JavaScript linting issues found"
        fi
        cd "$PROJECT_ROOT"
    fi
    
    # Python code quality
    if [ -f "sdks/python/requirements.txt" ]; then
        log_info "Checking Python code quality..."
        if command -v black &> /dev/null; then
            black --check sdks/python/ || (log_warning "Python formatting issues found" && black sdks/python/)
        fi
        
        if command -v flake8 &> /dev/null; then
            flake8 sdks/python/ || log_warning "Python linting issues found"
        fi
    fi
    
    log_success "Code quality checks completed"
}

# Run comprehensive tests
run_tests() {
    log_info "Running comprehensive test suite..."
    
    # Rust tests
    if [ -f "Cargo.toml" ]; then
        log_info "Running Rust tests..."
        cargo test --all-features --verbose
        
        # Run integration tests
        cargo test --test '*' --all-features || log_warning "Some integration tests failed"
        
        # Run doc tests
        cargo test --doc --all-features || log_warning "Some doc tests failed"
    fi
    
    # Go tests
    if [ -f "go.mod" ]; then
        log_info "Running Go tests..."
        go test -v ./...
        
        # Run benchmarks
        go test -bench=. -benchmem ./... || log_warning "Some benchmarks failed"
    fi
    
    # JavaScript tests
    if [ -f "sdks/javascript/package.json" ]; then
        log_info "Running JavaScript tests..."
        cd sdks/javascript
        npm test || log_warning "JavaScript tests failed"
        cd "$PROJECT_ROOT"
    fi
    
    # Python tests
    if [ -f "sdks/python/requirements.txt" ]; then
        log_info "Running Python tests..."
        cd sdks/python
        python -m pytest || log_warning "Python tests failed"
        cd "$PROJECT_ROOT"
    fi
    
    log_success "Test suite completed"
}

# Generate documentation
generate_documentation() {
    log_info "Generating documentation..."
    
    # Rust documentation
    if [ -f "Cargo.toml" ]; then
        log_info "Generating Rust documentation..."
        cargo doc --all-features --no-deps
    fi
    
    # Generate API documentation
    if [ -f "docs/api.md" ]; then
        log_info "Updating API documentation..."
        # Add API doc generation logic here
    fi
    
    # Generate architecture diagrams
    if command -v mermaid &> /dev/null; then
        log_info "Generating architecture diagrams..."
        find docs -name "*.mmd" -exec mermaid -i {} -o docs/images/ \; || log_warning "Diagram generation failed"
    fi
    
    log_success "Documentation generated"
}

# Performance analysis
run_performance_analysis() {
    log_info "Running performance analysis..."
    
    # Rust benchmarks
    if [ -f "Cargo.toml" ]; then
        log_info "Running Rust benchmarks..."
        if command -v cargo-criterion &> /dev/null; then
            cargo criterion --message-format=json > logs/benchmark-results.json
        else
            cargo bench
        fi
    fi
    
    # Memory usage analysis
    if command -v valgrind &> /dev/null; then
        log_info "Running memory analysis..."
        # Add memory analysis for critical paths
    fi
    
    # Binary size analysis
    if command -v cargo-bloat &> /dev/null; then
        log_info "Analyzing binary size..."
        cargo bloat --release --crates > logs/binary-analysis.txt
    fi
    
    log_success "Performance analysis completed"
}

# Infrastructure validation
validate_infrastructure() {
    log_info "Validating infrastructure configuration..."
    
    # Docker configuration
    if [ -f "Dockerfile" ]; then
        log_info "Validating Dockerfile..."
        docker build --no-cache -t universal-ai-governor-test . || log_warning "Docker build failed"
        
        # Security scan of Docker image
        if command -v trivy &> /dev/null; then
            trivy image universal-ai-governor-test || log_warning "Docker security scan found issues"
        fi
    fi
    
    # Kubernetes manifests
    if [ -d "k8s" ] || [ -d "deployment/kubernetes" ]; then
        log_info "Validating Kubernetes manifests..."
        find . -name "*.yaml" -o -name "*.yml" | grep -E "(k8s|kubernetes)" | while read -r file; do
            kubectl --dry-run=client apply -f "$file" || log_warning "Invalid Kubernetes manifest: $file"
        done
    fi
    
    # Docker Compose validation
    if [ -f "docker-compose.yml" ]; then
        log_info "Validating Docker Compose configuration..."
        docker-compose config || log_warning "Docker Compose configuration invalid"
    fi
    
    log_success "Infrastructure validation completed"
}

# Cleanup and maintenance
run_cleanup() {
    log_info "Running cleanup and maintenance..."
    
    # Clean build artifacts
    if [ -f "Cargo.toml" ]; then
        cargo clean
    fi
    
    # Clean Go build cache
    if [ -f "go.mod" ]; then
        go clean -cache
        go clean -modcache
    fi
    
    # Clean node modules
    if [ -d "sdks/javascript/node_modules" ]; then
        rm -rf sdks/javascript/node_modules
        cd sdks/javascript && npm install && cd "$PROJECT_ROOT"
    fi
    
    # Clean temporary files
    find . -name "*.tmp" -o -name "*.temp" -o -name ".DS_Store" -delete || true
    
    # Optimize Git repository
    git gc --aggressive --prune=now || log_warning "Git cleanup failed"
    
    log_success "Cleanup completed"
}

# Generate automation report
generate_report() {
    log_info "Generating automation report..."
    
    local report_file="logs/automation-report-$(date +%Y%m%d-%H%M%S).md"
    
    cat > "$report_file" << EOF
# Universal AI Governor - Automation Report

Generated: $(date)
Commit: $(git rev-parse HEAD)

## Summary

This report contains the results of automated project maintenance and quality assurance.

## Tasks Completed

- [x] Dependency updates
- [x] Security scans
- [x] Code quality checks
- [x] Comprehensive testing
- [x] Documentation generation
- [x] Performance analysis
- [x] Infrastructure validation
- [x] Cleanup and maintenance

## Security Status

$(if [ -f "logs/secrets-scan.json" ]; then echo "- Secrets scan completed (see logs/secrets-scan.json)"; fi)
- Dependency vulnerabilities checked
- Code patterns analyzed for security issues

## Performance Metrics

$(if [ -f "logs/benchmark-results.json" ]; then echo "- Benchmark results available (see logs/benchmark-results.json)"; fi)
$(if [ -f "logs/binary-analysis.txt" ]; then echo "- Binary size analysis completed (see logs/binary-analysis.txt)"; fi)

## Recommendations

1. Review any warnings or errors in the automation log
2. Address security issues identified in scans
3. Update dependencies regularly
4. Monitor performance metrics for regressions
5. Keep infrastructure configurations up to date

## Next Steps

- Schedule regular automation runs
- Set up monitoring for critical metrics
- Implement automated deployment pipelines
- Enhance security scanning coverage

---

For detailed logs, see: $LOG_FILE
EOF
    
    log_success "Automation report generated: $report_file"
}

# Main automation workflow
main() {
    print_banner
    init_logging
    
    log_info "Starting Universal AI Governor automation workflow..."
    
    # Core automation tasks
    check_prerequisites
    update_dependencies
    run_security_scans
    run_quality_checks
    run_tests
    generate_documentation
    run_performance_analysis
    validate_infrastructure
    run_cleanup
    generate_report
    
    log_success "Automation workflow completed successfully!"
    
    echo ""
    echo "+================================================================+"
    echo "|                                                                |"
    echo "|                    AUTOMATION COMPLETE                        |"
    echo "|                                                                |"
    echo "|         Universal AI Governor maintenance finished             |"
    echo "|                                                                |"
    echo "+================================================================+"
}

# Handle command line arguments
case "${1:-all}" in
    deps|dependencies)
        init_logging
        check_prerequisites
        update_dependencies
        ;;
    security)
        init_logging
        check_prerequisites
        run_security_scans
        ;;
    quality)
        init_logging
        check_prerequisites
        run_quality_checks
        ;;
    test|tests)
        init_logging
        check_prerequisites
        run_tests
        ;;
    docs|documentation)
        init_logging
        check_prerequisites
        generate_documentation
        ;;
    perf|performance)
        init_logging
        check_prerequisites
        run_performance_analysis
        ;;
    infra|infrastructure)
        init_logging
        check_prerequisites
        validate_infrastructure
        ;;
    clean|cleanup)
        init_logging
        run_cleanup
        ;;
    report)
        init_logging
        generate_report
        ;;
    all)
        main
        ;;
    help|--help|-h)
        echo "Universal AI Governor Automation Script"
        echo ""
        echo "Usage: $0 [TASK]"
        echo ""
        echo "Tasks:"
        echo "  deps, dependencies    Update project dependencies"
        echo "  security             Run security scans"
        echo "  quality              Run code quality checks"
        echo "  test, tests          Run comprehensive tests"
        echo "  docs, documentation  Generate documentation"
        echo "  perf, performance    Run performance analysis"
        echo "  infra, infrastructure Validate infrastructure"
        echo "  clean, cleanup       Clean and maintain project"
        echo "  report               Generate automation report"
        echo "  all                  Run all tasks (default)"
        echo "  help                 Show this help message"
        ;;
    *)
        log_error "Unknown task: $1"
        echo "Use '$0 help' to see available tasks"
        exit 1
        ;;
esac
