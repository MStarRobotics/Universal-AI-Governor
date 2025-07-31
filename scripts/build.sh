#!/bin/bash
# Universal AI Governor - Build Script
# 
# I got tired of remembering all the different build flags and options,
# so I automated the whole build process. This handles everything from
# basic compilation to full release builds with optimizations.

set -euo pipefail

# Colors for output (because life's too short for plain text)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration - you can override these with environment variables
BUILD_TYPE="${BUILD_TYPE:-release}"
TARGET_ARCH="${TARGET_ARCH:-$(uname -m)}"
FEATURES="${FEATURES:-all-features}"
PARALLEL_JOBS="${PARALLEL_JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

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

# Print a nice banner
print_banner() {
    echo -e "${BLUE}"
    echo "+================================================================+"
    echo "|                                                                |"
    echo "|              UNIVERSAL AI GOVERNOR BUILD                      |"
    echo "|                                                                |"
    echo "|         Building with optimizations and validations           |"
    echo "|                                                                |"
    echo "+================================================================+"
    echo -e "${NC}"
}

# Show what we're building
show_config() {
    log_info "Build Configuration:"
    echo "  Build Type: $BUILD_TYPE"
    echo "  Target Architecture: $TARGET_ARCH"
    echo "  Features: $FEATURES"
    echo "  Parallel Jobs: $PARALLEL_JOBS"
    echo "  Rust Version: $(rustc --version)"
    echo "  Cargo Version: $(cargo --version)"
    echo ""
}

# Clean up previous builds if requested
clean_build() {
    if [ "${CLEAN:-false}" = "true" ]; then
        log_info "Cleaning previous builds..."
        cargo clean
        rm -rf target/
        log_success "Build artifacts cleaned"
    fi
}

# Check that code is properly formatted
check_formatting() {
    log_info "Checking code formatting..."
    if cargo fmt --all -- --check; then
        log_success "Code formatting is correct"
    else
        log_error "Code formatting issues found. Run 'cargo fmt' to fix."
        exit 1
    fi
}

# Run clippy to catch common issues
run_clippy() {
    log_info "Running Clippy lints..."
    if cargo clippy --all-targets --$FEATURES -- -D warnings; then
        log_success "Clippy checks passed"
    else
        log_error "Clippy found issues that need to be fixed"
        exit 1
    fi
}

# Check for security vulnerabilities in dependencies
run_security_audit() {
    log_info "Running security audit..."
    if command -v cargo-audit >/dev/null 2>&1; then
        if cargo audit; then
            log_success "Security audit passed"
        else
            log_warning "Security audit found issues (continuing build anyway)"
        fi
    else
        log_warning "cargo-audit not installed, skipping security audit"
    fi
}

# Check dependency licenses and other policies
check_dependencies() {
    log_info "Checking dependency policies..."
    if command -v cargo-deny >/dev/null 2>&1; then
        if cargo deny check; then
            log_success "Dependency checks passed"
        else
            log_warning "Dependency checks found issues (continuing anyway)"
        fi
    else
        log_warning "cargo-deny not installed, skipping dependency checks"
    fi
}

# Build documentation
build_docs() {
    if [ "${BUILD_DOCS:-true}" = "true" ]; then
        log_info "Building documentation..."
        cargo doc --$FEATURES --no-deps
        log_success "Documentation built successfully"
    fi
}

# Run the test suite
run_tests() {
    if [ "${RUN_TESTS:-true}" = "true" ]; then
        log_info "Running test suite..."
        
        # Unit tests
        log_info "Running unit tests..."
        cargo test --$FEATURES --lib
        
        # Integration tests
        log_info "Running integration tests..."
        cargo test --$FEATURES --test '*'
        
        # Doc tests
        log_info "Running documentation tests..."
        cargo test --$FEATURES --doc
        
        log_success "All tests passed"
    fi
}

# Build the main binary
build_binary() {
    log_info "Building Universal AI Governor binary..."
    
    local build_flags=""
    if [ "$BUILD_TYPE" = "release" ]; then
        build_flags="--release"
        # Set some aggressive optimization flags for release builds
        export RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C lto=fat -C codegen-units=1"
    fi
    
    # Actually build the thing
    cargo build $build_flags --$FEATURES --jobs $PARALLEL_JOBS
    
    log_success "Binary built successfully"
}

# Build any additional tools
build_tools() {
    log_info "Building additional tools..."
    
    # Check if we have any binary tools to build
    local tools_built=0
    for tool in policy-generator threat-analyzer audit-viewer; do
        if [ -f "src/bin/$tool.rs" ]; then
            log_info "Building $tool..."
            cargo build --bin $tool --$FEATURES
            tools_built=$((tools_built + 1))
        fi
    done
    
    if [ $tools_built -gt 0 ]; then
        log_success "Built $tools_built additional tools"
    else
        log_info "No additional tools to build"
    fi
}

# Generate build metadata
generate_metadata() {
    log_info "Generating build metadata..."
    
    local target_dir="target"
    if [ "$BUILD_TYPE" = "release" ]; then
        target_dir="target/release"
    else
        target_dir="target/debug"
    fi
    
    # Create a build info file
    cat > "$target_dir/build-info.json" << EOF
{
    "build_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "build_type": "$BUILD_TYPE",
    "target_arch": "$TARGET_ARCH",
    "features": "$FEATURES",
    "rust_version": "$(rustc --version)",
    "cargo_version": "$(cargo --version)",
    "git_commit": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')",
    "git_branch": "$(git branch --show-current 2>/dev/null || echo 'unknown')",
    "builder": "$(whoami)@$(hostname)"
}
EOF
    
    log_success "Build metadata generated"
}

# Make sure the build actually worked
verify_build() {
    log_info "Verifying build artifacts..."
    
    local target_dir="target"
    if [ "$BUILD_TYPE" = "release" ]; then
        target_dir="target/release"
    else
        target_dir="target/debug"
    fi
    
    # Check that the main binary exists and is executable
    if [ -f "$target_dir/universal-ai-governor" ]; then
        log_success "Main binary found: $target_dir/universal-ai-governor"
        
        # Show some info about the binary
        ls -lh "$target_dir/universal-ai-governor"
        
        # Quick test that it can at least start up
        if "$target_dir/universal-ai-governor" --version >/dev/null 2>&1; then
            log_success "Binary executes successfully"
        else
            log_warning "Binary execution test failed (might be missing dependencies)"
        fi
    else
        log_error "Main binary not found! Something went wrong with the build."
        exit 1
    fi
}

# Create a distribution package if requested
create_package() {
    if [ "${CREATE_PACKAGE:-false}" = "true" ]; then
        log_info "Creating distribution package..."
        
        local package_name="universal-ai-governor-$(date +%Y%m%d-%H%M%S)"
        local package_dir="dist/$package_name"
        
        mkdir -p "$package_dir"
        
        # Copy the binary
        if [ "$BUILD_TYPE" = "release" ]; then
            cp target/release/universal-ai-governor "$package_dir/"
        else
            cp target/debug/universal-ai-governor "$package_dir/"
        fi
        
        # Copy important files
        cp -r config "$package_dir/"
        cp -r docs "$package_dir/"
        cp README.md LICENSE CHANGELOG.md "$package_dir/" 2>/dev/null || true
        
        # Create the archive
        cd dist
        tar -czf "$package_name.tar.gz" "$package_name"
        cd ..
        
        log_success "Package created: dist/$package_name.tar.gz"
    fi
}

# Run performance benchmarks if requested
run_benchmarks() {
    if [ "${RUN_BENCHMARKS:-false}" = "true" ]; then
        log_info "Running performance benchmarks..."
        
        if command -v cargo-criterion >/dev/null 2>&1; then
            cargo criterion
            log_success "Benchmarks completed"
        else
            log_warning "cargo-criterion not installed, running basic benchmarks"
            cargo bench
        fi
    fi
}

# Analyze the build for performance characteristics
analyze_performance() {
    if [ "${ANALYZE_PERFORMANCE:-false}" = "true" ]; then
        log_info "Analyzing performance characteristics..."
        
        local target_dir="target"
        if [ "$BUILD_TYPE" = "release" ]; then
            target_dir="target/release"
        else
            target_dir="target/debug"
        fi
        
        # Show binary size
        local size=$(du -h "$target_dir/universal-ai-governor" | cut -f1)
        log_info "Binary size: $size"
        
        # Analyze what's taking up space (if cargo-bloat is available)
        if command -v cargo-bloat >/dev/null 2>&1; then
            log_info "Analyzing binary bloat..."
            cargo bloat --release --crates | head -20
        fi
        
        log_success "Performance analysis completed"
    fi
}

# Show a summary of what we built
show_summary() {
    echo -e "${GREEN}"
    echo "+================================================================+"
    echo "|                                                                |"
    echo "|                    BUILD COMPLETE!                            |"
    echo "|                                                                |"
    echo "|  Build artifacts:                                              |"
    
    local target_dir="target"
    if [ "$BUILD_TYPE" = "release" ]; then
        target_dir="target/release"
    else
        target_dir="target/debug"
    fi
    
    if [ -f "$target_dir/universal-ai-governor" ]; then
        local size=$(du -h "$target_dir/universal-ai-governor" | cut -f1)
        echo "|    Binary: $target_dir/universal-ai-governor ($size)"
    fi
    
    echo "|                                                                |"
    echo "|  Next steps:                                                   |"
    echo "|    Run: $target_dir/universal-ai-governor --help               |"
    echo "|    Test: cargo test --$FEATURES                                |"
    echo "|    Deploy: docker build -t universal-ai-governor .             |"
    echo "|                                                                |"
    echo "+================================================================+"
    echo -e "${NC}"
}

# Main build function
main() {
    print_banner
    show_config
    
    # Pre-build checks and cleanup
    clean_build
    check_formatting
    run_clippy
    run_security_audit
    check_dependencies
    
    # Build everything
    build_docs
    run_tests
    build_binary
    build_tools
    
    # Post-build tasks
    generate_metadata
    verify_build
    create_package
    run_benchmarks
    analyze_performance
    
    show_summary
    
    log_success "Build process completed successfully!"
}

# Handle command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            BUILD_TYPE="debug"
            shift
            ;;
        --release)
            BUILD_TYPE="release"
            shift
            ;;
        --clean)
            CLEAN="true"
            shift
            ;;
        --no-tests)
            RUN_TESTS="false"
            shift
            ;;
        --no-docs)
            BUILD_DOCS="false"
            shift
            ;;
        --package)
            CREATE_PACKAGE="true"
            shift
            ;;
        --benchmarks)
            RUN_BENCHMARKS="true"
            shift
            ;;
        --analyze)
            ANALYZE_PERFORMANCE="true"
            shift
            ;;
        --help)
            echo "Universal AI Governor Build Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --debug              Build in debug mode (default: release)"
            echo "  --release            Build in release mode"
            echo "  --clean              Clean previous builds first"
            echo "  --no-tests           Skip running tests"
            echo "  --no-docs            Skip building documentation"
            echo "  --package            Create distribution package"
            echo "  --benchmarks         Run performance benchmarks"
            echo "  --analyze            Analyze performance characteristics"
            echo "  --help               Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  BUILD_TYPE           Build type (debug/release)"
            echo "  TARGET_ARCH          Target architecture"
            echo "  FEATURES             Cargo features to enable"
            echo "  PARALLEL_JOBS        Number of parallel build jobs"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help to see available options"
            exit 1
            ;;
    esac
done

# Run the main build process
main "$@"

# Show build configuration
show_config() {
    log_info "Build Configuration:"
    echo "  Build Type: $BUILD_TYPE"
    echo "  Target Architecture: $TARGET_ARCH"
    echo "  Features: $FEATURES"
    echo "  Parallel Jobs: $PARALLEL_JOBS"
    echo "  Rust Version: $(rustc --version)"
    echo "  Cargo Version: $(cargo --version)"
    echo ""
}

# Clean previous builds
clean_build() {
    if [ "${CLEAN:-false}" = "true" ]; then
        log_info "Cleaning previous builds..."
        cargo clean
        rm -rf target/
        log_success "Build artifacts cleaned"
    fi
}

# Check code formatting
check_formatting() {
    log_info "Checking code formatting..."
    if cargo fmt --all -- --check; then
        log_success "Code formatting is correct"
    else
        log_error "Code formatting issues found. Run 'cargo fmt' to fix."
        exit 1
    fi
}

# Run clippy lints
run_clippy() {
    log_info "Running Clippy lints..."
    if cargo clippy --all-targets --$FEATURES -- -D warnings; then
        log_success "Clippy checks passed"
    else
        log_error "Clippy found issues"
        exit 1
    fi
}

# Run security audit
run_security_audit() {
    log_info "Running security audit..."
    if cargo audit; then
        log_success "Security audit passed"
    else
        log_warning "Security audit found issues (continuing build)"
    fi
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependency licenses and security..."
    if command -v cargo-deny >/dev/null 2>&1; then
        cargo deny check
        log_success "Dependency checks passed"
    else
        log_warning "cargo-deny not installed, skipping dependency checks"
    fi
}

# Build documentation
build_docs() {
    if [ "${BUILD_DOCS:-true}" = "true" ]; then
        log_info "Building documentation..."
        cargo doc --$FEATURES --no-deps
        log_success "Documentation built"
    fi
}

# Run tests
run_tests() {
    if [ "${RUN_TESTS:-true}" = "true" ]; then
        log_info "Running test suite..."
        
        # Unit tests
        cargo test --$FEATURES --lib
        
        # Integration tests
        cargo test --$FEATURES --test '*'
        
        # Doc tests
        cargo test --$FEATURES --doc
        
        log_success "All tests passed"
    fi
}

# Build the main binary
build_binary() {
    log_info "Building Universal AI Governor binary..."
    
    local build_flags=""
    if [ "$BUILD_TYPE" = "release" ]; then
        build_flags="--release"
    fi
    
    # Set optimization flags for release builds
    if [ "$BUILD_TYPE" = "release" ]; then
        export RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C lto=fat -C codegen-units=1"
    fi
    
    cargo build $build_flags --$FEATURES --jobs $PARALLEL_JOBS
    
    log_success "Binary built successfully"
}

# Build additional tools
build_tools() {
    log_info "Building additional tools..."
    
    # Build CLI tools
    for tool in policy-generator threat-analyzer audit-viewer; do
        if [ -f "src/bin/$tool.rs" ]; then
            log_info "Building $tool..."
            cargo build --bin $tool --$FEATURES
        fi
    done
    
    log_success "Tools built successfully"
}

# Generate build metadata
generate_metadata() {
    log_info "Generating build metadata..."
    
    local target_dir="target"
    if [ "$BUILD_TYPE" = "release" ]; then
        target_dir="target/release"
    else
        target_dir="target/debug"
    fi
    
    # Create build info
    cat > "$target_dir/build-info.json" << EOF
{
    "build_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "build_type": "$BUILD_TYPE",
    "target_arch": "$TARGET_ARCH",
    "features": "$FEATURES",
    "rust_version": "$(rustc --version)",
    "cargo_version": "$(cargo --version)",
    "git_commit": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')",
    "git_branch": "$(git branch --show-current 2>/dev/null || echo 'unknown')"
}
EOF
    
    log_success "Build metadata generated"
}

# Verify build artifacts
verify_build() {
    log_info "Verifying build artifacts..."
    
    local target_dir="target"
    if [ "$BUILD_TYPE" = "release" ]; then
        target_dir="target/release"
    else
        target_dir="target/debug"
    fi
    
    # Check main binary
    if [ -f "$target_dir/universal-ai-governor" ]; then
        log_success "Main binary found: $target_dir/universal-ai-governor"
        
        # Show binary info
        ls -lh "$target_dir/universal-ai-governor"
        
        # Test binary execution
        if "$target_dir/universal-ai-governor" --version >/dev/null 2>&1; then
            log_success "Binary executes successfully"
        else
            log_warning "Binary execution test failed"
        fi
    else
        log_error "Main binary not found!"
        exit 1
    fi
}

# Create distribution package
create_package() {
    if [ "${CREATE_PACKAGE:-false}" = "true" ]; then
        log_info "Creating distribution package..."
        
        local package_name="universal-ai-governor-$(date +%Y%m%d-%H%M%S)"
        local package_dir="dist/$package_name"
        
        mkdir -p "$package_dir"
        
        # Copy binary
        if [ "$BUILD_TYPE" = "release" ]; then
            cp target/release/universal-ai-governor "$package_dir/"
        else
            cp target/debug/universal-ai-governor "$package_dir/"
        fi
        
        # Copy configuration files
        cp -r config "$package_dir/"
        cp -r docs "$package_dir/"
        cp README.md LICENSE "$package_dir/"
        
        # Create archive
        cd dist
        tar -czf "$package_name.tar.gz" "$package_name"
        cd ..
        
        log_success "Package created: dist/$package_name.tar.gz"
    fi
}

# Performance benchmarks
run_benchmarks() {
    if [ "${RUN_BENCHMARKS:-false}" = "true" ]; then
        log_info "Running performance benchmarks..."
        
        if command -v cargo-criterion >/dev/null 2>&1; then
            cargo criterion
            log_success "Benchmarks completed"
        else
            log_warning "cargo-criterion not installed, skipping benchmarks"
        fi
    fi
}

# Memory and performance analysis
analyze_performance() {
    if [ "${ANALYZE_PERFORMANCE:-false}" = "true" ]; then
        log_info "Analyzing performance characteristics..."
        
        local target_dir="target"
        if [ "$BUILD_TYPE" = "release" ]; then
            target_dir="target/release"
        else
            target_dir="target/debug"
        fi
        
        # Binary size analysis
        log_info "Binary size: $(du -h $target_dir/universal-ai-governor | cut -f1)"
        
        # Dependency analysis
        if command -v cargo-bloat >/dev/null 2>&1; then
            cargo bloat --release --crates
        fi
        
        log_success "Performance analysis completed"
    fi
}

# Show build summary
show_summary() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                  ║"
    echo "║                    🎉 BUILD COMPLETE! 🎉                        ║"
    echo "║                                                                  ║"
    echo "║  Build artifacts:                                                ║"
    
    local target_dir="target"
    if [ "$BUILD_TYPE" = "release" ]; then
        target_dir="target/release"
    else
        target_dir="target/debug"
    fi
    
    if [ -f "$target_dir/universal-ai-governor" ]; then
        local size=$(du -h "$target_dir/universal-ai-governor" | cut -f1)
        echo "║    Binary: $target_dir/universal-ai-governor ($size)"
    fi
    
    echo "║                                                                  ║"
    echo "║  Next steps:                                                     ║"
    echo "║    Run: $target_dir/universal-ai-governor --help                 ║"
    echo "║    Test: cargo test --$FEATURES                                  ║"
    echo "║    Deploy: docker build -t universal-ai-governor .               ║"
    echo "║                                                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Main build function
main() {
    print_banner
    show_config
    
    # Pre-build checks
    clean_build
    check_formatting
    run_clippy
    run_security_audit
    check_dependencies
    
    # Build process
    build_docs
    run_tests
    build_binary
    build_tools
    
    # Post-build tasks
    generate_metadata
    verify_build
    create_package
    run_benchmarks
    analyze_performance
    
    show_summary
    
    log_success "Build process completed successfully!"
}

# Handle command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            BUILD_TYPE="debug"
            shift
            ;;
        --release)
            BUILD_TYPE="release"
            shift
            ;;
        --clean)
            CLEAN="true"
            shift
            ;;
        --no-tests)
            RUN_TESTS="false"
            shift
            ;;
        --no-docs)
            BUILD_DOCS="false"
            shift
            ;;
        --package)
            CREATE_PACKAGE="true"
            shift
            ;;
        --benchmarks)
            RUN_BENCHMARKS="true"
            shift
            ;;
        --analyze)
            ANALYZE_PERFORMANCE="true"
            shift
            ;;
        --help)
            echo "Universal AI Governor Build Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --debug              Build in debug mode (default: release)"
            echo "  --release            Build in release mode"
            echo "  --clean              Clean previous builds"
            echo "  --no-tests           Skip running tests"
            echo "  --no-docs            Skip building documentation"
            echo "  --package            Create distribution package"
            echo "  --benchmarks         Run performance benchmarks"
            echo "  --analyze            Analyze performance characteristics"
            echo "  --help               Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  BUILD_TYPE           Build type (debug/release)"
            echo "  TARGET_ARCH          Target architecture"
            echo "  FEATURES             Cargo features to enable"
            echo "  PARALLEL_JOBS        Number of parallel build jobs"
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
