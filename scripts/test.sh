#!/bin/bash
# Universal AI Governor - Comprehensive Test Suite
# Runs all tests including unit, integration, security, and performance tests

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_TYPE="${TEST_TYPE:-all}"
COVERAGE_THRESHOLD="${COVERAGE_THRESHOLD:-80}"
PARALLEL_JOBS="${PARALLEL_JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
GENERATE_REPORT="${GENERATE_REPORT:-true}"

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

# Print banner
print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                  ║"
    echo "║              🧪 UNIVERSAL AI GOVERNOR TESTS 🧪                  ║"
    echo "║                                                                  ║"
    echo "║         Comprehensive testing with security validation           ║"
    echo "║                                                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Show test configuration
show_config() {
    log_info "Test Configuration:"
    echo "  Test Type: $TEST_TYPE"
    echo "  Coverage Threshold: ${COVERAGE_THRESHOLD}%"
    echo "  Parallel Jobs: $PARALLEL_JOBS"
    echo "  Generate Report: $GENERATE_REPORT"
    echo "  Rust Version: $(rustc --version)"
    echo ""
}

# Setup test environment
setup_test_env() {
    log_info "Setting up test environment..."
    
    # Create test directories
    mkdir -p {test-data,test-logs,test-reports,test-coverage}
    
    # Set test environment variables
    export RUST_TEST_THREADS=$PARALLEL_JOBS
    export RUST_BACKTRACE=1
    export RUST_LOG=debug
    
    # Create test database
    export TEST_DATABASE_URL="sqlite://./test-data/test.db"
    
    # Generate test certificates
    if [ ! -f "test-data/test-cert.pem" ]; then
        openssl req -x509 -newkey rsa:2048 -keyout test-data/test-key.pem -out test-data/test-cert.pem -days 1 -nodes -subj "/CN=test"
    fi
    
    log_success "Test environment ready"
}

# Run unit tests
run_unit_tests() {
    if [ "$TEST_TYPE" = "all" ] || [ "$TEST_TYPE" = "unit" ]; then
        log_info "Running unit tests..."
        
        cargo test --lib --all-features --jobs $PARALLEL_JOBS -- --test-threads=$PARALLEL_JOBS
        
        log_success "Unit tests completed"
    fi
}

# Run integration tests
run_integration_tests() {
    if [ "$TEST_TYPE" = "all" ] || [ "$TEST_TYPE" = "integration" ]; then
        log_info "Running integration tests..."
        
        cargo test --test '*' --all-features --jobs $PARALLEL_JOBS -- --test-threads=$PARALLEL_JOBS
        
        log_success "Integration tests completed"
    fi
}

# Run documentation tests
run_doc_tests() {
    if [ "$TEST_TYPE" = "all" ] || [ "$TEST_TYPE" = "doc" ]; then
        log_info "Running documentation tests..."
        
        cargo test --doc --all-features
        
        log_success "Documentation tests completed"
    fi
}

# Run security tests
run_security_tests() {
    if [ "$TEST_TYPE" = "all" ] || [ "$TEST_TYPE" = "security" ]; then
        log_info "Running security tests..."
        
        # Adversarial prompt injection tests
        log_info "Testing adversarial prompt injection..."
        cargo test --test adversarial_tests --all-features
        
        # Authentication bypass tests
        log_info "Testing authentication bypass scenarios..."
        cargo test --test auth_bypass_tests --all-features
        
        # Cryptographic validation tests
        log_info "Testing cryptographic implementations..."
        cargo test --test crypto_tests --all-features
        
        # Hardware security tests (if available)
        if [ "${TPM_AVAILABLE:-false}" = "true" ]; then
            log_info "Testing TPM integration..."
            cargo test --test tpm_tests --all-features
        fi
        
        log_success "Security tests completed"
    fi
}

# Run performance tests
run_performance_tests() {
    if [ "$TEST_TYPE" = "all" ] || [ "$TEST_TYPE" = "performance" ]; then
        log_info "Running performance tests..."
        
        # Benchmark tests
        if command -v cargo-criterion >/dev/null 2>&1; then
            cargo criterion --message-format=json > test-reports/benchmark-results.json
        else
            cargo bench --all-features
        fi
        
        # Load testing
        log_info "Running load tests..."
        cargo test --test load_tests --all-features --release
        
        # Memory usage tests
        log_info "Testing memory usage..."
        cargo test --test memory_tests --all-features --release
        
        log_success "Performance tests completed"
    fi
}

# Run chaos engineering tests
run_chaos_tests() {
    if [ "$TEST_TYPE" = "all" ] || [ "$TEST_TYPE" = "chaos" ]; then
        log_info "Running chaos engineering tests..."
        
        # Network partition tests
        log_info "Testing network partitions..."
        cargo test --test network_chaos --all-features
        
        # Resource exhaustion tests
        log_info "Testing resource exhaustion..."
        cargo test --test resource_chaos --all-features
        
        # Hardware failure simulation
        log_info "Testing hardware failure scenarios..."
        cargo test --test hardware_chaos --all-features
        
        log_success "Chaos engineering tests completed"
    fi
}

# Run compliance tests
run_compliance_tests() {
    if [ "$TEST_TYPE" = "all" ] || [ "$TEST_TYPE" = "compliance" ]; then
        log_info "Running compliance tests..."
        
        # GDPR compliance tests
        log_info "Testing GDPR compliance..."
        cargo test --test gdpr_compliance --all-features
        
        # HIPAA compliance tests
        log_info "Testing HIPAA compliance..."
        cargo test --test hipaa_compliance --all-features
        
        # SOC2 compliance tests
        log_info "Testing SOC2 compliance..."
        cargo test --test soc2_compliance --all-features
        
        log_success "Compliance tests completed"
    fi
}

# Generate code coverage
generate_coverage() {
    if [ "$GENERATE_REPORT" = "true" ]; then
        log_info "Generating code coverage report..."
        
        if command -v cargo-tarpaulin >/dev/null 2>&1; then
            cargo tarpaulin \
                --all-features \
                --workspace \
                --timeout 300 \
                --out Html \
                --output-dir test-coverage \
                --exclude-files 'target/*' 'tests/*' 'benches/*'
            
            # Check coverage threshold
            local coverage=$(cargo tarpaulin --all-features --workspace --print-summary | grep -o '[0-9.]*%' | head -1 | sed 's/%//')
            if (( $(echo "$coverage >= $COVERAGE_THRESHOLD" | bc -l) )); then
                log_success "Code coverage: ${coverage}% (threshold: ${COVERAGE_THRESHOLD}%)"
            else
                log_warning "Code coverage: ${coverage}% is below threshold: ${COVERAGE_THRESHOLD}%"
            fi
        else
            log_warning "cargo-tarpaulin not installed, skipping coverage report"
        fi
    fi
}

# Run mutation testing
run_mutation_tests() {
    if [ "$TEST_TYPE" = "all" ] || [ "$TEST_TYPE" = "mutation" ]; then
        log_info "Running mutation tests..."
        
        if command -v cargo-mutants >/dev/null 2>&1; then
            cargo mutants --timeout 60 --output test-reports/mutation-results.json
            log_success "Mutation testing completed"
        else
            log_warning "cargo-mutants not installed, skipping mutation tests"
        fi
    fi
}

# Run property-based tests
run_property_tests() {
    if [ "$TEST_TYPE" = "all" ] || [ "$TEST_TYPE" = "property" ]; then
        log_info "Running property-based tests..."
        
        # QuickCheck-style property tests
        cargo test --test property_tests --all-features
        
        log_success "Property-based tests completed"
    fi
}

# Run fuzz tests
run_fuzz_tests() {
    if [ "$TEST_TYPE" = "all" ] || [ "$TEST_TYPE" = "fuzz" ]; then
        log_info "Running fuzz tests..."
        
        if command -v cargo-fuzz >/dev/null 2>&1; then
            # Run each fuzz target for a short duration
            local fuzz_targets=(
                "policy_parser"
                "request_validator"
                "crypto_operations"
                "multimedia_processor"
            )
            
            for target in "${fuzz_targets[@]}"; do
                if [ -f "fuzz/fuzz_targets/${target}.rs" ]; then
                    log_info "Fuzzing $target..."
                    timeout 60 cargo fuzz run "$target" || true
                fi
            done
            
            log_success "Fuzz testing completed"
        else
            log_warning "cargo-fuzz not installed, skipping fuzz tests"
        fi
    fi
}

# Validate test results
validate_results() {
    log_info "Validating test results..."
    
    local failed_tests=0
    
    # Check for test failures in logs
    if grep -q "test result: FAILED" test-logs/*.log 2>/dev/null; then
        log_error "Some tests failed"
        failed_tests=$((failed_tests + 1))
    fi
    
    # Check coverage threshold
    if [ -f "test-coverage/tarpaulin-report.html" ]; then
        local coverage=$(grep -o '[0-9.]*%' test-coverage/tarpaulin-report.html | head -1 | sed 's/%//')
        if (( $(echo "$coverage < $COVERAGE_THRESHOLD" | bc -l) )); then
            log_error "Coverage below threshold: ${coverage}% < ${COVERAGE_THRESHOLD}%"
            failed_tests=$((failed_tests + 1))
        fi
    fi
    
    if [ $failed_tests -eq 0 ]; then
        log_success "All test validations passed"
        return 0
    else
        log_error "$failed_tests validation(s) failed"
        return 1
    fi
}

# Generate test report
generate_test_report() {
    if [ "$GENERATE_REPORT" = "true" ]; then
        log_info "Generating comprehensive test report..."
        
        local report_file="test-reports/test-report-$(date +%Y%m%d-%H%M%S).html"
        
        cat > "$report_file" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Universal AI Governor - Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; }
        .success { border-left-color: #27ae60; }
        .warning { border-left-color: #f39c12; }
        .error { border-left-color: #e74c3c; }
        .metric { display: inline-block; margin: 10px; padding: 10px; background: #ecf0f1; border-radius: 3px; }
        pre { background: #2c3e50; color: white; padding: 15px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🧪 Universal AI Governor - Test Report</h1>
        <p>Generated: $(date)</p>
        <p>Test Type: $TEST_TYPE</p>
    </div>
EOF

        # Add test results sections
        echo '<div class="section success"><h2>✅ Test Summary</h2>' >> "$report_file"
        
        # Unit tests
        if [ -f "test-logs/unit-tests.log" ]; then
            local unit_passed=$(grep -c "test result: ok" test-logs/unit-tests.log || echo "0")
            echo "<div class=\"metric\">Unit Tests Passed: $unit_passed</div>" >> "$report_file"
        fi
        
        # Integration tests
        if [ -f "test-logs/integration-tests.log" ]; then
            local integration_passed=$(grep -c "test result: ok" test-logs/integration-tests.log || echo "0")
            echo "<div class=\"metric\">Integration Tests Passed: $integration_passed</div>" >> "$report_file"
        fi
        
        # Coverage
        if [ -f "test-coverage/tarpaulin-report.html" ]; then
            local coverage=$(grep -o '[0-9.]*%' test-coverage/tarpaulin-report.html | head -1)
            echo "<div class=\"metric\">Code Coverage: $coverage</div>" >> "$report_file"
        fi
        
        echo '</div>' >> "$report_file"
        
        # Add detailed sections for each test type
        for test_type in unit integration security performance; do
            if [ -f "test-logs/${test_type}-tests.log" ]; then
                echo "<div class=\"section\"><h2>📊 ${test_type^} Tests</h2>" >> "$report_file"
                echo "<pre>$(tail -50 test-logs/${test_type}-tests.log)</pre>" >> "$report_file"
                echo "</div>" >> "$report_file"
            fi
        done
        
        echo '</body></html>' >> "$report_file"
        
        log_success "Test report generated: $report_file"
    fi
}

# Cleanup test environment
cleanup_test_env() {
    log_info "Cleaning up test environment..."
    
    # Remove temporary test files
    rm -f test-data/test.db*
    rm -f test-data/test-*.pem
    
    # Archive test logs
    if [ -d "test-logs" ] && [ "$(ls -A test-logs)" ]; then
        tar -czf "test-reports/test-logs-$(date +%Y%m%d-%H%M%S).tar.gz" test-logs/
        rm -rf test-logs/*
    fi
    
    log_success "Test environment cleaned up"
}

# Main test function
main() {
    print_banner
    show_config
    
    # Setup
    setup_test_env
    
    # Create log directory
    mkdir -p test-logs
    
    # Run test suites
    run_unit_tests 2>&1 | tee test-logs/unit-tests.log
    run_integration_tests 2>&1 | tee test-logs/integration-tests.log
    run_doc_tests 2>&1 | tee test-logs/doc-tests.log
    run_security_tests 2>&1 | tee test-logs/security-tests.log
    run_performance_tests 2>&1 | tee test-logs/performance-tests.log
    run_chaos_tests 2>&1 | tee test-logs/chaos-tests.log
    run_compliance_tests 2>&1 | tee test-logs/compliance-tests.log
    run_property_tests 2>&1 | tee test-logs/property-tests.log
    run_mutation_tests 2>&1 | tee test-logs/mutation-tests.log
    run_fuzz_tests 2>&1 | tee test-logs/fuzz-tests.log
    
    # Generate reports
    generate_coverage
    generate_test_report
    
    # Validate and cleanup
    if validate_results; then
        cleanup_test_env
        log_success "All tests completed successfully! 🎉"
        exit 0
    else
        log_error "Some tests failed! ❌"
        exit 1
    fi
}

# Handle command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --type)
            TEST_TYPE="$2"
            shift 2
            ;;
        --coverage)
            COVERAGE_THRESHOLD="$2"
            shift 2
            ;;
        --jobs)
            PARALLEL_JOBS="$2"
            shift 2
            ;;
        --no-report)
            GENERATE_REPORT="false"
            shift
            ;;
        --help)
            echo "Universal AI Governor Test Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --type TYPE          Test type (all/unit/integration/security/performance/chaos/compliance/property/mutation/fuzz)"
            echo "  --coverage PERCENT   Coverage threshold (default: 80)"
            echo "  --jobs NUMBER        Number of parallel jobs"
            echo "  --no-report          Skip generating HTML report"
            echo "  --help               Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  TEST_TYPE            Test type to run"
            echo "  COVERAGE_THRESHOLD   Minimum coverage percentage"
            echo "  PARALLEL_JOBS        Number of parallel test jobs"
            echo "  TPM_AVAILABLE        Enable TPM-specific tests"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main function
main "$@"
