#!/bin/bash
# Universal AI Governor - Deployment Script
# Automated deployment with security validation and rollback capabilities

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DEPLOYMENT_ENV="${DEPLOYMENT_ENV:-staging}"
DEPLOYMENT_TYPE="${DEPLOYMENT_TYPE:-docker}"
HEALTH_CHECK_TIMEOUT="${HEALTH_CHECK_TIMEOUT:-300}"
ROLLBACK_ON_FAILURE="${ROLLBACK_ON_FAILURE:-true}"
BACKUP_BEFORE_DEPLOY="${BACKUP_BEFORE_DEPLOY:-true}"

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
    echo "║              🚀 UNIVERSAL AI GOVERNOR DEPLOY 🚀                 ║"
    echo "║                                                                  ║"
    echo "║         Automated deployment with security validation            ║"
    echo "║                                                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Show deployment configuration
show_config() {
    log_info "Deployment Configuration:"
    echo "  Environment: $DEPLOYMENT_ENV"
    echo "  Type: $DEPLOYMENT_TYPE"
    echo "  Health Check Timeout: ${HEALTH_CHECK_TIMEOUT}s"
    echo "  Rollback on Failure: $ROLLBACK_ON_FAILURE"
    echo "  Backup Before Deploy: $BACKUP_BEFORE_DEPLOY"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking deployment prerequisites..."
    
    # Check if binary exists
    if [ ! -f "target/release/universal-ai-governor" ]; then
        log_error "Release binary not found. Run './scripts/build.sh --release' first."
        exit 1
    fi
    
    # Check Docker if needed
    if [ "$DEPLOYMENT_TYPE" = "docker" ] || [ "$DEPLOYMENT_TYPE" = "kubernetes" ]; then
        if ! command -v docker >/dev/null 2>&1; then
            log_error "Docker is required for $DEPLOYMENT_TYPE deployment"
            exit 1
        fi
    fi
    
    # Check Kubernetes if needed
    if [ "$DEPLOYMENT_TYPE" = "kubernetes" ]; then
        if ! command -v kubectl >/dev/null 2>&1; then
            log_error "kubectl is required for Kubernetes deployment"
            exit 1
        fi
    fi
    
    # Check AWS CLI if needed
    if [ "$DEPLOYMENT_TYPE" = "aws" ]; then
        if ! command -v aws >/dev/null 2>&1; then
            log_error "AWS CLI is required for AWS deployment"
            exit 1
        fi
    fi
    
    log_success "Prerequisites check passed"
}

# Create backup
create_backup() {
    if [ "$BACKUP_BEFORE_DEPLOY" = "true" ]; then
        log_info "Creating backup before deployment..."
        
        local backup_dir="backups/$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$backup_dir"
        
        # Backup configuration
        if [ -d "config" ]; then
            cp -r config "$backup_dir/"
        fi
        
        # Backup data
        if [ -d "data" ]; then
            cp -r data "$backup_dir/"
        fi
        
        # Backup certificates
        if [ -d "certs" ]; then
            cp -r certs "$backup_dir/"
        fi
        
        # Create backup manifest
        cat > "$backup_dir/manifest.json" << EOF
{
    "backup_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "environment": "$DEPLOYMENT_ENV",
    "git_commit": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')",
    "version": "$(target/release/universal-ai-governor --version 2>/dev/null || echo 'unknown')"
}
EOF
        
        log_success "Backup created: $backup_dir"
        echo "$backup_dir" > .last_backup
    fi
}

# Build Docker image
build_docker_image() {
    if [ "$DEPLOYMENT_TYPE" = "docker" ] || [ "$DEPLOYMENT_TYPE" = "kubernetes" ]; then
        log_info "Building Docker image..."
        
        local image_tag="universal-ai-governor:$(date +%Y%m%d-%H%M%S)"
        local latest_tag="universal-ai-governor:latest"
        
        # Build image
        docker build -t "$image_tag" -t "$latest_tag" .
        
        # Security scan
        if command -v docker-scout >/dev/null 2>&1; then
            log_info "Running security scan on Docker image..."
            docker scout cves "$latest_tag" || log_warning "Security scan found issues"
        fi
        
        log_success "Docker image built: $image_tag"
        echo "$image_tag" > .last_image
    fi
}

# Deploy with Docker Compose
deploy_docker_compose() {
    log_info "Deploying with Docker Compose..."
    
    # Update environment-specific compose file
    local compose_file="docker-compose.${DEPLOYMENT_ENV}.yml"
    if [ ! -f "$compose_file" ]; then
        compose_file="docker-compose.yml"
    fi
    
    # Pull latest images
    docker-compose -f "$compose_file" pull
    
    # Deploy with rolling update
    docker-compose -f "$compose_file" up -d --remove-orphans
    
    log_success "Docker Compose deployment completed"
}

# Deploy to Kubernetes
deploy_kubernetes() {
    log_info "Deploying to Kubernetes..."
    
    local k8s_dir="k8s"
    if [ ! -d "$k8s_dir" ]; then
        log_error "Kubernetes manifests directory not found: $k8s_dir"
        exit 1
    fi
    
    # Apply ConfigMaps and Secrets first
    if [ -f "$k8s_dir/configmap.yaml" ]; then
        kubectl apply -f "$k8s_dir/configmap.yaml"
    fi
    
    if [ -f "$k8s_dir/secrets.yaml" ]; then
        kubectl apply -f "$k8s_dir/secrets.yaml"
    fi
    
    # Apply deployment
    kubectl apply -f "$k8s_dir/"
    
    # Wait for rollout
    kubectl rollout status deployment/universal-ai-governor --timeout=300s
    
    log_success "Kubernetes deployment completed"
}

# Deploy to AWS
deploy_aws() {
    log_info "Deploying to AWS..."
    
    case "${AWS_SERVICE:-ecs}" in
        ecs)
            deploy_aws_ecs
            ;;
        lambda)
            deploy_aws_lambda
            ;;
        ec2)
            deploy_aws_ec2
            ;;
        *)
            log_error "Unsupported AWS service: ${AWS_SERVICE}"
            exit 1
            ;;
    esac
}

# Deploy to AWS ECS
deploy_aws_ecs() {
    log_info "Deploying to AWS ECS..."
    
    local cluster_name="${ECS_CLUSTER:-universal-ai-governor}"
    local service_name="${ECS_SERVICE:-universal-ai-governor}"
    
    # Update task definition
    aws ecs register-task-definition \
        --cli-input-json file://aws/task-definition.json
    
    # Update service
    aws ecs update-service \
        --cluster "$cluster_name" \
        --service "$service_name" \
        --force-new-deployment
    
    # Wait for deployment
    aws ecs wait services-stable \
        --cluster "$cluster_name" \
        --services "$service_name"
    
    log_success "AWS ECS deployment completed"
}

# Deploy to AWS Lambda
deploy_aws_lambda() {
    log_info "Deploying to AWS Lambda..."
    
    local function_name="${LAMBDA_FUNCTION:-universal-ai-governor}"
    
    # Package for Lambda
    zip -r lambda-deployment.zip target/lambda/universal-ai-governor bootstrap
    
    # Update function code
    aws lambda update-function-code \
        --function-name "$function_name" \
        --zip-file fileb://lambda-deployment.zip
    
    # Wait for update to complete
    aws lambda wait function-updated \
        --function-name "$function_name"
    
    log_success "AWS Lambda deployment completed"
}

# Deploy to AWS EC2
deploy_aws_ec2() {
    log_info "Deploying to AWS EC2..."
    
    local instance_ids="${EC2_INSTANCES}"
    if [ -z "$instance_ids" ]; then
        log_error "EC2_INSTANCES environment variable not set"
        exit 1
    fi
    
    # Use AWS Systems Manager to deploy
    aws ssm send-command \
        --instance-ids $instance_ids \
        --document-name "AWS-RunShellScript" \
        --parameters 'commands=["cd /opt/universal-ai-governor && ./scripts/update.sh"]'
    
    log_success "AWS EC2 deployment initiated"
}

# Perform health checks
health_check() {
    log_info "Performing health checks..."
    
    local endpoint="${HEALTH_CHECK_ENDPOINT:-http://localhost:8080/health}"
    local timeout=$HEALTH_CHECK_TIMEOUT
    local interval=5
    local elapsed=0
    
    while [ $elapsed -lt $timeout ]; do
        if curl -f -s "$endpoint" >/dev/null 2>&1; then
            log_success "Health check passed"
            return 0
        fi
        
        log_info "Waiting for service to be healthy... (${elapsed}s/${timeout}s)"
        sleep $interval
        elapsed=$((elapsed + interval))
    done
    
    log_error "Health check failed after ${timeout}s"
    return 1
}

# Run smoke tests
run_smoke_tests() {
    log_info "Running smoke tests..."
    
    local base_url="${SMOKE_TEST_URL:-http://localhost:8080}"
    
    # Test basic endpoints
    local endpoints=(
        "/health"
        "/metrics"
        "/api/v1/status"
    )
    
    for endpoint in "${endpoints[@]}"; do
        if curl -f -s "${base_url}${endpoint}" >/dev/null; then
            log_success "Smoke test passed: $endpoint"
        else
            log_error "Smoke test failed: $endpoint"
            return 1
        fi
    done
    
    log_success "All smoke tests passed"
}

# Rollback deployment
rollback_deployment() {
    log_warning "Rolling back deployment..."
    
    case $DEPLOYMENT_TYPE in
        docker)
            if [ -f ".last_backup" ]; then
                local backup_dir=$(cat .last_backup)
                log_info "Restoring from backup: $backup_dir"
                
                # Restore configuration
                if [ -d "$backup_dir/config" ]; then
                    cp -r "$backup_dir/config" .
                fi
                
                # Restart services
                docker-compose restart
            fi
            ;;
        kubernetes)
            kubectl rollout undo deployment/universal-ai-governor
            kubectl rollout status deployment/universal-ai-governor
            ;;
        aws)
            case "${AWS_SERVICE:-ecs}" in
                ecs)
                    # Rollback to previous task definition
                    aws ecs update-service \
                        --cluster "${ECS_CLUSTER:-universal-ai-governor}" \
                        --service "${ECS_SERVICE:-universal-ai-governor}" \
                        --task-definition "$(aws ecs describe-services \
                            --cluster "${ECS_CLUSTER:-universal-ai-governor}" \
                            --services "${ECS_SERVICE:-universal-ai-governor}" \
                            --query 'services[0].deployments[1].taskDefinition' \
                            --output text)"
                    ;;
            esac
            ;;
    esac
    
    log_success "Rollback completed"
}

# Update monitoring and alerting
update_monitoring() {
    log_info "Updating monitoring configuration..."
    
    # Update Prometheus configuration
    if [ -f "monitoring/prometheus/prometheus.yml" ]; then
        # Reload Prometheus configuration
        if command -v curl >/dev/null 2>&1; then
            curl -X POST http://localhost:9090/-/reload 2>/dev/null || true
        fi
    fi
    
    # Update Grafana dashboards
    if [ -d "monitoring/grafana/dashboards" ]; then
        log_info "Grafana dashboards available for manual import"
    fi
    
    log_success "Monitoring configuration updated"
}

# Send deployment notification
send_notification() {
    local status=$1
    local message=$2
    
    if [ -n "${SLACK_WEBHOOK:-}" ]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"🚀 Universal AI Governor Deployment\\n**Environment:** $DEPLOYMENT_ENV\\n**Status:** $status\\n**Message:** $message\"}" \
            "$SLACK_WEBHOOK" 2>/dev/null || true
    fi
    
    if [ -n "${DISCORD_WEBHOOK:-}" ]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"content\":\"🚀 **Universal AI Governor Deployment**\\n**Environment:** $DEPLOYMENT_ENV\\n**Status:** $status\\n**Message:** $message\"}" \
            "$DISCORD_WEBHOOK" 2>/dev/null || true
    fi
}

# Main deployment function
main() {
    print_banner
    show_config
    
    # Pre-deployment
    check_prerequisites
    create_backup
    
    # Build phase
    build_docker_image
    
    # Deployment phase
    local deployment_success=true
    
    case $DEPLOYMENT_TYPE in
        docker)
            deploy_docker_compose || deployment_success=false
            ;;
        kubernetes)
            deploy_kubernetes || deployment_success=false
            ;;
        aws)
            deploy_aws || deployment_success=false
            ;;
        *)
            log_error "Unsupported deployment type: $DEPLOYMENT_TYPE"
            exit 1
            ;;
    esac
    
    # Post-deployment validation
    if [ "$deployment_success" = "true" ]; then
        if health_check && run_smoke_tests; then
            update_monitoring
            send_notification "SUCCESS" "Deployment completed successfully"
            log_success "Deployment completed successfully!"
        else
            deployment_success=false
        fi
    fi
    
    # Handle deployment failure
    if [ "$deployment_success" = "false" ]; then
        send_notification "FAILED" "Deployment failed, initiating rollback"
        
        if [ "$ROLLBACK_ON_FAILURE" = "true" ]; then
            rollback_deployment
            send_notification "ROLLBACK" "Rollback completed"
        fi
        
        log_error "Deployment failed!"
        exit 1
    fi
}

# Handle command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --env)
            DEPLOYMENT_ENV="$2"
            shift 2
            ;;
        --type)
            DEPLOYMENT_TYPE="$2"
            shift 2
            ;;
        --no-backup)
            BACKUP_BEFORE_DEPLOY="false"
            shift
            ;;
        --no-rollback)
            ROLLBACK_ON_FAILURE="false"
            shift
            ;;
        --timeout)
            HEALTH_CHECK_TIMEOUT="$2"
            shift 2
            ;;
        --help)
            echo "Universal AI Governor Deployment Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --env ENV            Deployment environment (staging/production)"
            echo "  --type TYPE          Deployment type (docker/kubernetes/aws)"
            echo "  --no-backup          Skip creating backup before deployment"
            echo "  --no-rollback        Disable automatic rollback on failure"
            echo "  --timeout SECONDS    Health check timeout (default: 300)"
            echo "  --help               Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  DEPLOYMENT_ENV       Deployment environment"
            echo "  DEPLOYMENT_TYPE      Deployment type"
            echo "  HEALTH_CHECK_ENDPOINT Health check URL"
            echo "  SLACK_WEBHOOK        Slack notification webhook"
            echo "  DISCORD_WEBHOOK      Discord notification webhook"
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
