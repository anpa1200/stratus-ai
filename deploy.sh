#!/usr/bin/env bash
# StratusAI deployment script
# Runs Terraform, builds the Docker image, pushes to ECR, and optionally triggers a scan.
#
# Usage:
#   ./deploy.sh                     # Deploy infrastructure + build + push
#   ./deploy.sh --run               # Deploy + trigger a scan immediately
#   ./deploy.sh --build-only        # Build + push image only (infra already deployed)
#   ./deploy.sh --run-only          # Trigger scan only (infra + image already deployed)
#   ./deploy.sh --destroy           # Destroy all infrastructure
#   ./deploy.sh --tf-dir ./terraform/examples/scheduled  # Use a specific Terraform config

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
TF_DIR="${TF_DIR:-./terraform}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
AWS_REGION="${AWS_REGION:-us-east-1}"
RUN_AFTER_DEPLOY=false
BUILD_ONLY=false
RUN_ONLY=false
DESTROY=false

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --run)          RUN_AFTER_DEPLOY=true ;;
    --build-only)   BUILD_ONLY=true ;;
    --run-only)     RUN_ONLY=true ;;
    --destroy)      DESTROY=true ;;
    --tf-dir)       TF_DIR="$2"; shift ;;
    --image-tag)    IMAGE_TAG="$2"; shift ;;
    --region)       AWS_REGION="$2"; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
  shift
done

# ── Helper functions ──────────────────────────────────────────────────────────
check_dependencies() {
  local missing=()
  for cmd in aws docker terraform; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "ERROR: Missing required tools: ${missing[*]}"
    echo "  aws:       https://aws.amazon.com/cli/"
    echo "  docker:    https://docs.docker.com/get-docker/"
    echo "  terraform: https://developer.hashicorp.com/terraform/install"
    exit 1
  fi
}

tf_output() {
  terraform -chdir="$TF_DIR" output -raw "$1" 2>/dev/null || echo ""
}

# ── Pre-flight ────────────────────────────────────────────────────────────────
check_dependencies

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              StratusAI — Deployment Tool                  ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ── Destroy mode ──────────────────────────────────────────────────────────────
if $DESTROY; then
  echo "⚠️  This will destroy ALL StratusAI infrastructure."
  read -r -p "Type 'yes' to confirm: " confirm
  [[ "$confirm" == "yes" ]] || { echo "Aborted."; exit 0; }
  terraform -chdir="$TF_DIR" destroy -auto-approve
  echo "✓ Infrastructure destroyed."
  exit 0
fi

# ── Terraform deploy ──────────────────────────────────────────────────────────
if ! $BUILD_ONLY && ! $RUN_ONLY; then
  echo "► Initializing Terraform..."
  terraform -chdir="$TF_DIR" init -upgrade -input=false

  echo ""
  echo "► Planning infrastructure changes..."
  terraform -chdir="$TF_DIR" plan -input=false -out=/tmp/stratusai.tfplan

  echo ""
  echo "► Applying infrastructure..."
  terraform -chdir="$TF_DIR" apply -input=false /tmp/stratusai.tfplan
  echo ""
  echo "✓ Infrastructure deployed."
fi

# ── Get Terraform outputs ─────────────────────────────────────────────────────
ECR_URL=$(tf_output "ecr_repository_url")
CLUSTER_NAME=$(tf_output "ecs_cluster_name")
TASK_FAMILY=$(tf_output "task_definition_family")
SECURITY_GROUP=$(tf_output "security_group_id")
LOG_GROUP=$(tf_output "log_group_name")
REPORTS_BUCKET=$(tf_output "reports_bucket_name")
SUBNET_IDS=$(tf_output "subnet_ids" | tr ',' '\n' | head -1 | tr -d '[]" ')

if [[ -z "$ECR_URL" ]]; then
  echo "ERROR: Could not get ECR repository URL from Terraform output."
  echo "  Run 'terraform -chdir=$TF_DIR output' to check state."
  exit 1
fi

# ── Docker build + ECR push ───────────────────────────────────────────────────
if ! $RUN_ONLY; then
  echo ""
  echo "► Authenticating Docker to ECR..."
  aws ecr get-login-password --region "$AWS_REGION" \
    | docker login --username AWS --password-stdin \
        "$(echo "$ECR_URL" | cut -d/ -f1)"

  echo ""
  echo "► Building Docker image..."
  docker build -t stratusai:build .

  FULL_TAG="${ECR_URL}:${IMAGE_TAG}"
  docker tag stratusai:build "$FULL_TAG"

  echo ""
  echo "► Pushing image to ECR: $FULL_TAG"
  docker push "$FULL_TAG"
  echo "✓ Image pushed."
fi

# ── Trigger scan ──────────────────────────────────────────────────────────────
if $RUN_AFTER_DEPLOY || $RUN_ONLY; then
  if [[ -z "$CLUSTER_NAME" || -z "$TASK_FAMILY" || -z "$SUBNET_IDS" ]]; then
    echo "ERROR: Missing ECS details from Terraform output."
    echo "  CLUSTER_NAME=$CLUSTER_NAME"
    echo "  TASK_FAMILY=$TASK_FAMILY"
    echo "  SUBNET_IDS=$SUBNET_IDS"
    exit 1
  fi

  echo ""
  echo "► Triggering ECS scan task..."
  TASK_ARN=$(aws ecs run-task \
    --cluster "$CLUSTER_NAME" \
    --task-definition "$TASK_FAMILY" \
    --launch-type FARGATE \
    --network-configuration "awsvpcConfiguration={subnets=[$SUBNET_IDS],securityGroups=[$SECURITY_GROUP],assignPublicIp=ENABLED}" \
    --region "$AWS_REGION" \
    --query "tasks[0].taskArn" \
    --output text)

  echo "✓ Scan started: $TASK_ARN"
  echo ""
  echo "  Watch logs:"
  echo "    aws logs tail $LOG_GROUP --follow"
  echo ""
  echo "  Check task status:"
  echo "    aws ecs describe-tasks --cluster $CLUSTER_NAME --tasks $TASK_ARN --region $AWS_REGION"
  echo ""
  echo "  Reports will appear at:"
  echo "    s3://$REPORTS_BUCKET/reports/"
  echo "    https://s3.console.aws.amazon.com/s3/buckets/$REPORTS_BUCKET"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                    DEPLOYMENT COMPLETE                    ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "  ECR Image:    $ECR_URL:$IMAGE_TAG"
echo "  ECS Cluster:  $CLUSTER_NAME"
echo "  Reports:      s3://$REPORTS_BUCKET/reports/"
echo "  Logs:         $LOG_GROUP"
echo ""
echo "  Trigger a scan manually:"
echo "    aws ecs run-task \\"
echo "      --cluster $CLUSTER_NAME \\"
echo "      --task-definition $TASK_FAMILY \\"
echo "      --launch-type FARGATE \\"
echo "      --network-configuration \"awsvpcConfiguration={subnets=[$SUBNET_IDS],securityGroups=[$SECURITY_GROUP],assignPublicIp=ENABLED}\" \\"
echo "      --region $AWS_REGION"
echo ""
