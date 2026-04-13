# SOC Platform Phase 7-10 Deployment Guide

## Quick Start (Local Development)

```bash
# Build and start all services
docker compose -f soc-platform/docker-compose.yml up --build

# Verify services are healthy
curl http://localhost:8000/health
```

## Kubernetes Deployment (Production)

### Prerequisites
- Kubernetes 1.24+
- cert-manager installed
- nginx-ingress-controller
- helm 3+ (optional)

### Deploy to Kubernetes

```bash
# 1. Create namespace and secrets
kubectl apply -f infrastructure/k8s/namespace-and-secrets.yaml

# 2. Update secrets with real values
kubectl edit secret soc-secrets -n soc-platform

# 3. Deploy API
kubectl apply -f infrastructure/k8s/api-deployment.yaml

# 4. Verify deployment
kubectl rollout status deployment/soc-api -n soc-platform
kubectl get pods -n soc-platform

# 5. Check service
kubectl get svc -n soc-platform
```

## NGINX Reverse Proxy Setup

### Standalone Installation

```bash
# Install NGINX
sudo apt-get install nginx

# Copy config
sudo cp nginx/soc-platform.conf /etc/nginx/sites-available/

# Enable site
sudo ln -s /etc/nginx/sites-available/soc-platform.conf /etc/nginx/sites-enabled/

# Test config
sudo nginx -t

# Start NGINX
sudo systemctl start nginx
sudo systemctl enable nginx
```

### HTTPS Setup with Let's Encrypt

```bash
# Install cert-bot
sudo apt-get install certbot python3-certbot-nginx

# Get certificate
sudo certbot certonly --nginx -d soc.example.com

# Update nginx config with cert paths
sudo sed -i 's|/etc/nginx/certs/tls.crt|/etc/letsencrypt/live/soc.example.com/fullchain.pem|g' /etc/nginx/sites-available/soc-platform.conf
sudo sed -i 's|/etc/nginx/certs/tls.key|/etc/letsencrypt/live/soc.example.com/privkey.pem|g' /etc/nginx/sites-available/soc-platform.conf

# Auto-renew certs
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer
```

## AWS Deployment

### Using ECR + ECS

```bash
# 1. Build Docker image
docker build -t soc-api backend/

# 2. Tag for ECR
aws ecr get-authorization-token --region us-east-1 | docker login --username AWS --password-stdin $(aws sts get-caller-identity --query Account --output text).dkr.ecr.us-east-1.amazonaws.com

docker tag soc-api:latest $(aws sts get-caller-identity --query Account --output text).dkr.ecr.us-east-1.amazonaws.com/soc-api:latest

# 3. Push to ECR
docker push $(aws sts get-caller-identity --query Account --output text).dkr.ecr.us-east-1.amazonaws.com/soc-api:latest

# 4. Create ECS cluster
aws ecs create-cluster --cluster-name soc-platform

# 5.  Deploy task definition (create task-definition.json first)
aws ecs register-task-definition --cli-input-json file://task-definition.json

# 6. Create service
aws ecs create-service \
  --cluster soc-platform \
  --service-name soc-api \
  --task-definition soc-api:1 \
  --desired-count 3 \
  --load-balancers targetGroupArn=arn:aws:elasticloadbalancing:...,containerName=soc-api,containerPort=8000
```

### Using CloudFormation

```bash
aws cloudformation create-stack \
  --stack-name soc-platform \
  --template-body file://infrastructure/cf/soc-platform.yaml
```

## GCP Deployment

### Using Cloud Run

```bash
# Build and push container
gcloud builds submit --tag gcr.io/PROJECT_ID/soc-api

# Deploy
gcloud run deploy soc-api \
  --image gcr.io/PROJECT_ID/soc-api:latest \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars DATABASE_URL=postgresql://...,REDIS_URL=redis://...
```

### Using GKE

```bash
# Create GKE cluster
gcloud container clusters create soc-platform \
  --zone us-central1-a \
  --num-nodes 3 \
  --machine-type n1-standard-2

# Get credentials
gcloud container clusters get-credentials soc-platform --zone us-central1-a

# Deploy to GKE
kubectl apply -f infrastructure/k8s/
```

## Environment Variables

### Production Secrets (Set in your deployment)

```bash
# Database
DATABASE_URL=postgresql://user:pass@host:5432/socdb

# Redis
REDIS_URL=redis://host:6379/0

# Kafka
KAFKA_BOOTSTRAP_SERVERS=kafka:9092
KAFKA_LOGS_TOPIC=logs

# JWT
JWT_SECRET=your-secret-key-min-32-chars

# Integrations
IDENTITY_PROVIDER=okta  # or azure_ad, auth0
NETWORK_PROVIDER=cloudflare  # or aws, azure
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
TEAMS_WEBHOOK_URL=https://outlook.webhook.office.com/...
EMAIL_RECIPIENTS=security-team@company.com,soc@company.com

# Billing (optional)
STRIPE_API_KEY=sk_live_...
```

## Distributed Agent Deployment (Production)

Use the endpoint collector at [agents/soc_agent.py](agents/soc_agent.py) to stream host telemetry to the platform.

### Recommended Runtime Flags

```bash
cd agents
python soc_agent.py \
  --api-url https://your-soc.example.com/api \
  --api-key YOUR_API_KEY \
  --tenant-id YOUR_TENANT_ID \
  --interval 15 \
  --batch-size 250 \
  --max-retries 4 \
  --retry-base-delay 1.0 \
  --retry-max-delay 16.0
```

### Recommended Production Values

- `batch-size=250`: higher throughput with bounded request sizes.
- `max-retries=4`: resilience against transient API/network failures.
- `retry-base-delay=1.0`: fast first retry.
- `retry-max-delay=16.0`: caps exponential retry backoff.

### Environment Variable Equivalents

```bash
SOC_AGENT_BATCH_SIZE=250
SOC_AGENT_MAX_RETRIES=4
SOC_AGENT_RETRY_BASE_DELAY=1.0
SOC_AGENT_RETRY_MAX_DELAY=16.0
```

Use the public API gateway URL in `--api-url` (for example `https://your-soc.example.com/api`) so ingest requests reach `/telemetry/ingest` through NGINX.

### Rollback (Agent Tuning)

If telemetry volume or retry pressure is too high after rollout, revert to conservative defaults and restart agent processes:

```bash
SOC_AGENT_BATCH_SIZE=100
SOC_AGENT_MAX_RETRIES=2
SOC_AGENT_RETRY_BASE_DELAY=1.0
SOC_AGENT_RETRY_MAX_DELAY=8.0
```

Equivalent runtime flag rollback:

```bash
--batch-size 100 --max-retries 2 --retry-base-delay 1.0 --retry-max-delay 8.0
```

## Monitoring & Observability

### Prometheus Scrape Config

```yaml
scrape_configs:
- job_name: 'soc-api'
  static_configs:
  - targets: ['localhost:9090']
  metrics_path: '/metrics'
```

### Log Aggregation

```bash
# With Elasticsearch + Logstash + Kibana
# Forward logs from:
# - API container logs
# - NGINX access/error logs
# - Database slow query logs
```

## Scaling Considerations

### CPU/Memory Limits
- API: 500m CPU / 1Gi Memory per pod
- Database: 4 CPU / 8GB Memory
- Redis: 2 CPU / 4GB Memory
- Kafka: 2 CPU / 4GB Memory

### Horizontal Scaling
- API: Auto-scales 3-10 replicas based on CPU/Memory
- Database: Use read replicas for scaling read workload
- Redis: Use Redis Cluster for HA
- Kafka: Add brokers as needed

## Security Hardening

### Network Security
- Network policies restrict pod-to-pod communication
- Only allow ingress from LB
- Restrict egress to required services

### Pod Security
- Non-root containers
- Read-only root filesystem
- Dropped capabilities
- Resource limits enforced

### Data Security
- Encryption in transit (HTTPS/TLS)
- Encryption at rest (PostgreSQL EDB, Redis encryption)
- Secrets stored in K8s Secrets or HashiCorp Vault

## Backup & Disaster Recovery

### Database Backups

```bash
# Automated daily backups to S3
pg_dump -Fc soc-db | \
  aws s3 cp - s3://soc-backups/$(date +%Y%m%d).dump

# Point-in-time recovery with WAL archival
wal_level = replica
archive_mode = on
archive_command = 'aws s3 cp %p s3://soc-wal-archive/%f'
```

### RTO/RPO Targets
- RTO: 1 hour
- RPO: 15 minutes

## Troubleshooting

### Common Issues

```bash
# API pod not starting
kubectl logs -n soc-platform deployment/soc-api
kubectl describe pod -n soc-platform <pod-name>

# Database connection issues
kubectl exec -n soc-platform <pod-name> -- psql $DATABASE_URL -c "SELECT 1"

# Redis connectivity
kubectl exec -n soc-platform <pod-name> -- redis-cli -u $REDIS_URL PING

# NGINX reverse proxy issues
sudo tail -f /var/log/nginx/error.log
sudo nginx -t
```

## Maintenance

### Rolling Updates

```bash
# Update container image
kubectl set image deployment/soc-api \
  soc-api=soc-api:v2.0.1 \
  -n soc-platform

# Monitor rollout
kubectl rollout status deployment/soc-api -n soc-platform
```

### Database Migrations

```bash
# Run migrations automatically via init container
# Or manually:
kubectl exec -n soc-platform <pod-name> -- \
  python -m alembic upgrade head
```
