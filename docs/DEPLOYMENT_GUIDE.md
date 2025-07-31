# Universal AI Governor Deployment Guide

```
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                        DEPLOYMENT ARCHITECTURE                              ║
    ╠══════════════════════════════════════════════════════════════════════════════╣
    ║                                                                              ║
    ║    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐        ║
    ║    │   PRODUCTION    │    │     STAGING     │    │   DEVELOPMENT   │        ║
    ║    │   ENVIRONMENT   │    │   ENVIRONMENT   │    │   ENVIRONMENT   │        ║
    ║    │                 │    │                 │    │                 │        ║
    ║    │ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │        ║
    ║    │ │ KUBERNETES  │ │    │ │ DOCKER      │ │    │ │ LOCAL       │ │        ║
    ║    │ │ CLUSTER     │ │    │ │ COMPOSE     │ │    │ │ BINARY      │ │        ║
    ║    │ │ HA SETUP    │ │    │ │ TESTING     │ │    │ │ DEVELOPMENT │ │        ║
    ║    │ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │        ║
    ║    └─────────────────┘    └─────────────────┘    └─────────────────┘        ║
    ║                                                                              ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
```

## Production Deployment

### Kubernetes Deployment

For production environments, Kubernetes provides the most robust deployment option with high availability, auto-scaling, and rolling updates.

#### Prerequisites
- Kubernetes cluster (version 1.24+)
- kubectl configured with cluster access
- Helm 3.x installed
- Persistent storage provisioner
- Load balancer controller

#### Step 1: Prepare Namespace and Secrets

```bash
# Create dedicated namespace
kubectl create namespace ai-governor-prod

# Create TLS certificates secret
kubectl create secret tls ai-governor-tls \
  --cert=path/to/certificate.crt \
  --key=path/to/private.key \
  -n ai-governor-prod

# Create application secrets
kubectl create secret generic ai-governor-secrets \
  --from-literal=jwt-secret="your-jwt-secret-here" \
  --from-literal=postgres-password="secure-db-password" \
  --from-literal=redis-password="secure-cache-password" \
  -n ai-governor-prod
```

#### Step 2: Deploy with Helm

```bash
# Add Helm repository (if published)
helm repo add ai-governor https://charts.ai-governor.io
helm repo update

# Deploy with production values
helm install ai-governor-prod ai-governor/universal-ai-governor \
  --namespace ai-governor-prod \
  --values production-values.yaml \
  --wait --timeout 10m
```

### Docker Compose Deployment

For smaller production environments or staging, Docker Compose provides a simpler deployment option.

#### Step 1: Prepare Environment

```bash
# Clone repository
git clone https://github.com/your-org/universal-ai-governor.git
cd universal-ai-governor

# Create production environment file
cp .env.example .env.production
# Edit .env.production with your configuration
```

#### Step 2: Deploy Stack

```bash
# Deploy production stack
docker-compose -f docker-compose.prod.yml up -d

# Verify deployment
docker-compose -f docker-compose.prod.yml ps
```

## Security Hardening

### Network Security

```
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                        NETWORK SECURITY LAYERS                         │
    ├─────────────────────────────────────────────────────────────────────────┤
    │                                                                         │
    │  LAYER 1: PERIMETER DEFENSE                                             │
    │  ┌─────────────────────────────────────────────────────────────────────┐│
    │  │ • Web Application Firewall (WAF)                                   ││
    │  │ • DDoS Protection Service                                           ││
    │  │ • Geographic IP Blocking                                            ││
    │  │ • Rate Limiting at Edge                                             ││
    │  └─────────────────────────────────────────────────────────────────────┘│
    │                                                                         │
    │  LAYER 2: NETWORK SEGMENTATION                                          │
    │  ┌─────────────────────────────────────────────────────────────────────┐│
    │  │ • Private Subnets for Backend Services                              ││
    │  │ • Network Access Control Lists (NACLs)                              ││
    │  │ • Security Groups with Least Privilege                              ││
    │  │ • VPN Access for Administrative Tasks                               ││
    │  └─────────────────────────────────────────────────────────────────────┘│
    │                                                                         │
    │  LAYER 3: APPLICATION SECURITY                                          │
    │  ┌─────────────────────────────────────────────────────────────────────┐│
    │  │ • TLS 1.3 Encryption for All Communications                         ││
    │  │ • Mutual TLS (mTLS) for Service-to-Service                          ││
    │  │ • Certificate Pinning and Rotation                                  ││
    │  │ • API Gateway with Authentication                                   ││
    │  └─────────────────────────────────────────────────────────────────────┘│
    └─────────────────────────────────────────────────────────────────────────┘
```

### Container Security

#### Security Scanning
```bash
# Scan container images for vulnerabilities
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image universal-ai-governor:latest

# Scan for secrets in code
docker run --rm -v $(pwd):/app \
  trufflesecurity/trufflehog filesystem /app
```

#### Runtime Security
```bash
# Run with security constraints
docker run -d \
  --name ai-governor \
  --read-only \
  --tmpfs /tmp \
  --tmpfs /var/run \
  --user 1001:1001 \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges \
  universal-ai-governor:latest
```

## Monitoring and Observability

### Metrics Collection

The system exposes comprehensive metrics for monitoring:

```bash
# Prometheus metrics endpoint
curl http://localhost:8080/metrics

# Key metrics to monitor:
# - ai_governor_requests_total
# - ai_governor_request_duration_seconds
# - ai_governor_policy_evaluations_total
# - ai_governor_threats_detected_total
# - ai_governor_errors_total
```

### Log Aggregation

Configure centralized logging for security and operational insights:

```yaml
# Fluentd configuration for log shipping
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluentd-config
data:
  fluent.conf: |
    <source>
      @type tail
      path /var/log/ai-governor/*.log
      pos_file /var/log/fluentd-ai-governor.log.pos
      tag ai-governor.*
      format json
    </source>
    
    <match ai-governor.**>
      @type elasticsearch
      host elasticsearch.logging.svc.cluster.local
      port 9200
      index_name ai-governor-logs
    </match>
```

## Backup and Disaster Recovery

### Database Backup Strategy

```bash
# Automated PostgreSQL backup
#!/bin/bash
BACKUP_DIR="/backups/postgres"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup
pg_dump -h postgres-host -U governor -d governor \
  --no-password --clean --create \
  > "${BACKUP_DIR}/governor_backup_${DATE}.sql"

# Compress backup
gzip "${BACKUP_DIR}/governor_backup_${DATE}.sql"

# Upload to secure storage
aws s3 cp "${BACKUP_DIR}/governor_backup_${DATE}.sql.gz" \
  s3://ai-governor-backups/postgres/
```

### Configuration Backup

```bash
# Backup Kubernetes configurations
kubectl get all,configmaps,secrets -n ai-governor-prod -o yaml \
  > ai-governor-k8s-backup-$(date +%Y%m%d).yaml

# Backup policy files
tar -czf policies-backup-$(date +%Y%m%d).tar.gz policies/
```

## Performance Optimization

### Resource Allocation

```yaml
# Kubernetes resource requests and limits
resources:
  requests:
    memory: "1Gi"
    cpu: "500m"
  limits:
    memory: "4Gi"
    cpu: "2000m"
```

### Horizontal Pod Autoscaling

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: ai-governor-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: ai-governor
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## Troubleshooting

### Common Issues

#### Issue: High Memory Usage
```bash
# Check memory usage
kubectl top pods -n ai-governor-prod

# Analyze memory leaks
kubectl exec -it ai-governor-pod -- /bin/sh
# Inside container:
ps aux --sort=-%mem | head
```

#### Issue: Database Connection Failures
```bash
# Check database connectivity
kubectl exec -it ai-governor-pod -- nc -zv postgres-service 5432

# Check database logs
kubectl logs postgres-pod -n ai-governor-prod
```

#### Issue: Certificate Expiration
```bash
# Check certificate expiration
openssl x509 -in certificate.crt -text -noout | grep "Not After"

# Renew certificates (example with cert-manager)
kubectl annotate certificate ai-governor-tls \
  cert-manager.io/issue-temporary-certificate="true"
```

This deployment guide provides comprehensive instructions for deploying the Universal AI Governor in production environments with proper security hardening and monitoring.
