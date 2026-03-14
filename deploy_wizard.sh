#!/usr/bin/env bash
# StratusAI — Deployment Wizard
# Interactively collects all deployment parameters for AWS or GCP,
# writes the appropriate terraform.tfvars, and deploys.
#
# Usage: ./deploy_wizard.sh

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "  ${CYAN}${*}${RESET}"; }
ok()      { echo -e "  ${GREEN}✓  ${*}${RESET}"; }
warn()    { echo -e "  ${YELLOW}⚠  ${*}${RESET}"; }
err()     { echo -e "  ${RED}✗  ${*}${RESET}"; }
section() { echo -e "\n${BOLD}${BLUE}── Step ${*}${RESET}"; echo; }
hr()      { echo -e "${BLUE}────────────────────────────────────────────────────────────${RESET}"; }

ask() {
  local prompt="$1" default="${2:-}"
  local display_default=""
  [[ -n "$default" ]] && display_default=" [${default}]"
  echo -en "  ${BOLD}${prompt}${display_default}: ${RESET}" >&2
  read -r reply
  echo "${reply:-$default}"
}

ask_secret() {
  local prompt="$1"
  echo -en "  ${BOLD}${prompt} (hidden): ${RESET}" >&2
  read -rs reply
  echo >&2
  echo "$reply"
}

# Prints numbered options then reads a choice; returns the number chosen.
# All display goes to stderr so $(...) capture works correctly.
ask_choice() {
  local prompt="$1" default="$2"; shift 2
  local opts=("$@") total="${#@}" i=1
  echo -e "  ${BOLD}${prompt}${RESET}" >&2
  for opt in "${opts[@]}"; do
    echo -e "    ${CYAN}${i})${RESET}  ${opt}" >&2
    ((i++))
  done
  local reply
  while true; do
    echo -en "  Enter 1-${total} ${BOLD}[${default}]${RESET}: " >&2
    read -r reply
    reply="${reply:-$default}"
    if [[ "$reply" =~ ^[0-9]+$ ]] && (( reply >= 1 && reply <= total )); then
      break
    fi
    echo -e "  ${RED}Please enter a number between 1 and ${total}.${RESET}" >&2
  done
  echo "$reply"
}

confirm() {
  echo -en "  ${BOLD}${1:-Continue?} [y/N]: ${RESET}"
  read -r reply
  [[ "${reply,,}" == "y" || "${reply,,}" == "yes" ]]
}

# ── Header ────────────────────────────────────────────────────────────────────
clear
echo
hr
echo -e "  ${BOLD}${MAGENTA}StratusAI — Deployment Wizard${RESET}"
echo -e "  Deploy StratusAI to ${BOLD}AWS${RESET} (ECS Fargate) or ${BOLD}GCP${RESET} (Cloud Run Job)"
hr
echo

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 0 — Choose cloud provider
# ═══════════════════════════════════════════════════════════════════════════════
section "0 — Target cloud platform"

echo -e "  Where do you want to deploy StratusAI?"
echo
PLATFORM_CHOICE=$(ask_choice "Platform" "1" \
  "AWS  — ECS Fargate + ECR + S3 + SSM + EventBridge" \
  "GCP  — Cloud Run Job + Artifact Registry + GCS + Secret Manager + Cloud Scheduler")

if [[ "$PLATFORM_CHOICE" == "1" ]]; then
  PLATFORM="aws"
  echo; ok "Deploying to AWS"
else
  PLATFORM="gcp"
  echo; ok "Deploying to GCP"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 1 — Check dependencies
# ═══════════════════════════════════════════════════════════════════════════════
section "1 — Checking dependencies"

MISSING=()
if [[ "$PLATFORM" == "aws" ]]; then
  REQUIRED_TOOLS=(aws docker terraform)
else
  REQUIRED_TOOLS=(gcloud docker terraform)
fi

for cmd in "${REQUIRED_TOOLS[@]}"; do
  if command -v "$cmd" &>/dev/null; then
    ok "$cmd  →  $(command -v "$cmd")"
  else
    err "$cmd not found"
    MISSING+=("$cmd")
  fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo
  warn "Install missing tools before deploying:"
  [[ " ${MISSING[*]} " == *" aws "* ]]       && info "aws:       https://aws.amazon.com/cli/"
  [[ " ${MISSING[*]} " == *" gcloud "* ]]    && info "gcloud:    https://cloud.google.com/sdk/docs/install"
  [[ " ${MISSING[*]} " == *" docker "* ]]    && info "docker:    https://docs.docker.com/get-docker/"
  [[ " ${MISSING[*]} " == *" terraform "* ]] && info "terraform: https://developer.hashicorp.com/terraform/install"
  exit 1
fi

# ═══════════════════════════════════════════════════════════════════════════════
# AWS DEPLOYMENT PATH
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$PLATFORM" == "aws" ]]; then

# ── AWS Step 2: Authentication ────────────────────────────────────────────────
section "2 — AWS authentication"

echo -e "  Available profiles:"
aws configure list-profiles 2>/dev/null | while read -r p; do echo "    • $p"; done || \
  info "(no profiles found — using environment credentials)"
echo

AWS_PROFILE=$(ask "AWS profile" "default")
PROFILE_ARG=""
[[ "$AWS_PROFILE" != "default" ]] && export AWS_PROFILE && PROFILE_ARG="--profile $AWS_PROFILE"

info "Verifying credentials..."
if CALLER=$(aws sts get-caller-identity $PROFILE_ARG --output json 2>/dev/null); then
  ACCOUNT_ID=$(echo "$CALLER" | grep -o '"Account": "[^"]*"' | cut -d'"' -f4)
  CALLER_ARN=$(echo "$CALLER" | grep -o '"Arn": "[^"]*"' | cut -d'"' -f4)
  ok "Authenticated:  ${CALLER_ARN}"
  ok "Account ID:     ${ACCOUNT_ID}"
else
  err "AWS authentication failed. Run 'aws configure' or set AWS_ACCESS_KEY_ID."
  exit 1
fi

# ── AWS Step 3: Basics ────────────────────────────────────────────────────────
section "3 — Deployment settings"

AWS_REGION=$(ask "AWS region" "us-east-1")
NAME_PREFIX=$(ask "Resource name prefix" "stratusai")
ENVIRONMENT=$(ask "Environment label (prod / staging)" "prod")

# ── AWS Step 4: Networking ────────────────────────────────────────────────────
section "4 — Networking (VPC & subnets)"

echo -e "  ECS Fargate tasks need a VPC and at least one public subnet."
echo
NET_CHOICE=$(ask_choice "VPC" "1" \
  "Auto — use existing default VPC (recommended)" \
  "Custom — specify VPC and subnet IDs")

VPC_ID=""; SUBNET_IDS=""
if [[ "$NET_CHOICE" == "2" ]]; then
  echo
  info "Fetching VPCs in ${AWS_REGION}..."
  aws ec2 describe-vpcs $PROFILE_ARG --region "$AWS_REGION" \
    --query 'Vpcs[*].[VpcId,CidrBlock,Tags[?Key==`Name`].Value|[0]]' \
    --output text 2>/dev/null | \
    while IFS=$'\t' read -r id cidr name; do
      printf "    %-22s  %-18s  %s\n" "$id" "$cidr" "${name:-<no name>}"
    done || warn "Could not list VPCs."
  echo
  VPC_ID=$(ask "VPC ID (e.g. vpc-0abc1234)")
  echo
  info "Fetching subnets for ${VPC_ID}..."
  aws ec2 describe-subnets $PROFILE_ARG --region "$AWS_REGION" \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
    --query 'Subnets[*].[SubnetId,AvailabilityZone,CidrBlock,Tags[?Key==`Name`].Value|[0]]' \
    --output text 2>/dev/null | \
    while IFS=$'\t' read -r id az cidr name; do
      printf "    %-24s  %-14s  %-18s  %s\n" "$id" "$az" "$cidr" "${name:-<no name>}"
    done || warn "Could not list subnets."
  echo
  SUBNET_IDS=$(ask "Subnet IDs (comma-separated, e.g. subnet-aaa,subnet-bbb)")
fi

# ── AWS Step 5: AI ────────────────────────────────────────────────────────────
section "5 — AI model & API key"

echo -e "    1) claude-sonnet-4-6          ${CYAN}Anthropic  ~\$0.08/scan  (recommended)${RESET}"
echo -e "    2) claude-haiku-4-5-20251001  ${CYAN}Anthropic  ~\$0.01/scan  (budget)${RESET}"
echo -e "    3) claude-opus-4-6            ${CYAN}Anthropic  ~\$0.30/scan  (best quality)${RESET}"
echo -e "    4) gpt-4o                     ${CYAN}OpenAI     ~\$0.10/scan${RESET}"
echo -e "    5) gemini-2.0-flash           ${CYAN}Google     ~\$0.005/scan (cheapest)${RESET}"
echo -e "    6) No AI                      ${CYAN}Free — raw scanner output only${RESET}"
echo
AI_CHOICE=$(ask_choice "Model" "1" \
  "claude-sonnet-4-6" "claude-haiku-4-5-20251001" "claude-opus-4-6" \
  "gpt-4o" "gemini-2.0-flash" "No AI")

ENABLE_AI="true"; AI_MODEL="claude-sonnet-4-6"; API_KEY=""
case "$AI_CHOICE" in
  1) AI_MODEL="claude-sonnet-4-6" ;;
  2) AI_MODEL="claude-haiku-4-5-20251001" ;;
  3) AI_MODEL="claude-opus-4-6" ;;
  4) AI_MODEL="gpt-4o" ;;
  5) AI_MODEL="gemini-2.0-flash" ;;
  6) ENABLE_AI="false" ;;
esac

if [[ "$ENABLE_AI" == "true" ]]; then
  echo
  case "$AI_MODEL" in
    claude-*) ENV_KEY="${ANTHROPIC_API_KEY:-}"; KEY_PREFIX="sk-ant-" ;;
    gpt-*)    ENV_KEY="${OPENAI_API_KEY:-}";    KEY_PREFIX="sk-" ;;
    gemini-*) ENV_KEY="${GOOGLE_API_KEY:-}";    KEY_PREFIX="AIza" ;;
  esac
  if [[ -n "$ENV_KEY" ]]; then
    ok "API key found in environment (${ENV_KEY:0:10}...)"
    API_KEY="$ENV_KEY"
  else
    API_KEY=$(ask_secret "API key")
  fi
  if [[ "$API_KEY" != ${KEY_PREFIX}* ]]; then
    warn "Key prefix doesn't match expected '${KEY_PREFIX}...' — double-check before deploying."
  fi
fi

# ── AWS Step 6: Scan config ────────────────────────────────────────────────────
section "6 — Scan configuration"

SCAN_REGIONS=$(ask "AWS regions to scan (comma-separated)" "$AWS_REGION")
echo
echo -e "  Minimum severity filter:"
SEV_CHOICE=$(ask_choice "Severity" "1" \
  "INFO (everything)" "LOW" "MEDIUM (recommended)" "HIGH" "CRITICAL (only showstoppers)")
case "$SEV_CHOICE" in
  1) SEVERITY="INFO" ;; 2) SEVERITY="LOW" ;; 3) SEVERITY="MEDIUM" ;;
  4) SEVERITY="HIGH" ;; 5) SEVERITY="CRITICAL" ;; *) SEVERITY="INFO" ;;
esac

echo
ENABLE_EXTERNAL="false"; EXTERNAL_TARGET=""
if confirm "Enable external scan (ports, SSL, headers, DNS)?"; then
  ENABLE_EXTERNAL="true"
  EXTERNAL_TARGET=$(ask "Hostname or IP to scan (e.g. api.example.com)")
fi

echo
SCAN_MODULES=$(ask "Modules to run (comma-separated, Enter = all)" "")
echo
ACCOUNT_CONTEXT=$(ask "Environment context for AI (e.g. 'Production fintech, PCI DSS')" "")

# ── AWS Step 7: Scheduler ─────────────────────────────────────────────────────
section "7 — Scheduled scans (optional)"

ENABLE_SCHEDULER="false"; SCHEDULE_EXPR="rate(7 days)"; NOTIFICATION_EMAIL=""
if confirm "Enable automatic scheduled scans via EventBridge?"; then
  ENABLE_SCHEDULER="true"
  echo
  echo -e "  Examples:  rate(7 days)   rate(1 day)   cron(0 8 * * ? *)"
  SCHEDULE_EXPR=$(ask "Schedule expression" "rate(7 days)")
  NOTIFICATION_EMAIL=$(ask "Alert email on scan completion (leave blank to skip)" "")
fi

# ── AWS Step 8: Run on deploy? ────────────────────────────────────────────────
section "8 — Post-deploy"

RUN_AFTER_DEPLOY=false
confirm "Trigger a scan immediately after deployment?" && RUN_AFTER_DEPLOY=true

# ── AWS Summary ───────────────────────────────────────────────────────────────
echo; hr
echo -e "  ${BOLD}AWS Deployment Summary${RESET}"; hr; echo
printf "  %-28s %s\n" "Account:"           "$ACCOUNT_ID"
printf "  %-28s %s\n" "Region:"            "$AWS_REGION"
printf "  %-28s %s\n" "Name prefix:"       "$NAME_PREFIX"
printf "  %-28s %s\n" "Environment:"       "$ENVIRONMENT"
echo
[[ -n "$VPC_ID" ]] && printf "  %-28s %s\n" "VPC:" "$VPC_ID" \
                   && printf "  %-28s %s\n" "Subnets:" "$SUBNET_IDS" \
                   || printf "  %-28s %s\n" "VPC:" "Default (auto-discovered)"
echo
printf "  %-28s %s\n" "AI enabled:"        "$ENABLE_AI"
[[ "$ENABLE_AI" == "true" ]] && printf "  %-28s %s\n" "AI model:" "$AI_MODEL"
[[ -n "$API_KEY" ]]          && printf "  %-28s %s\n" "API key:" "${API_KEY:0:10}..."
echo
printf "  %-28s %s\n" "Scan regions:"      "$SCAN_REGIONS"
printf "  %-28s %s\n" "Severity filter:"   "$SEVERITY"
printf "  %-28s %s\n" "External scan:"     "$ENABLE_EXTERNAL"
[[ -n "$EXTERNAL_TARGET" ]] && printf "  %-28s %s\n" "External target:" "$EXTERNAL_TARGET"
[[ -n "$SCAN_MODULES" ]]    && printf "  %-28s %s\n" "Modules:" "$SCAN_MODULES"
[[ -n "$ACCOUNT_CONTEXT" ]] && printf "  %-28s %s\n" "AI context:" "$ACCOUNT_CONTEXT"
echo
printf "  %-28s %s\n" "Scheduled scans:"   "$ENABLE_SCHEDULER"
[[ "$ENABLE_SCHEDULER" == "true" ]] && printf "  %-28s %s\n" "Schedule:" "$SCHEDULE_EXPR"
[[ -n "$NOTIFICATION_EMAIL" ]]      && printf "  %-28s %s\n" "Alert email:" "$NOTIFICATION_EMAIL"
echo
printf "  %-28s %s\n" "Run scan on deploy:" "$RUN_AFTER_DEPLOY"
echo; hr; echo

confirm "Write terraform/terraform.tfvars and deploy?" || { info "Cancelled."; exit 0; }

# ── Write AWS tfvars ──────────────────────────────────────────────────────────
TFVARS="./terraform/terraform.tfvars"
info "Writing ${TFVARS}..."

cat > "$TFVARS" <<TFVARS
# Generated by deploy_wizard.sh — $(date -u +"%Y-%m-%dT%H:%M:%SZ")

aws_region   = "${AWS_REGION}"
name_prefix  = "${NAME_PREFIX}"
environment  = "${ENVIRONMENT}"

TFVARS

if [[ -n "$VPC_ID" ]]; then
  echo "vpc_id     = \"${VPC_ID}\""  >> "$TFVARS"
  HCL_SUBNETS=$(echo "$SUBNET_IDS" | sed 's/[[:space:]]//g; s/,/", "/g')
  echo "subnet_ids = [\"${HCL_SUBNETS}\"]" >> "$TFVARS"
fi

cat >> "$TFVARS" <<TFVARS

enable_ai    = ${ENABLE_AI}
claude_model = "${AI_MODEL}"
TFVARS
[[ -n "$API_KEY" ]] && echo "anthropic_api_key = \"${API_KEY}\"" >> "$TFVARS"

cat >> "$TFVARS" <<TFVARS

scan_regions         = "${SCAN_REGIONS}"
scan_severity        = "${SEVERITY}"
enable_external_scan = ${ENABLE_EXTERNAL}
TFVARS
[[ -n "$EXTERNAL_TARGET" ]] && echo "external_scan_target = \"${EXTERNAL_TARGET}\"" >> "$TFVARS"
[[ -n "$SCAN_MODULES" ]]    && echo "scan_modules         = \"${SCAN_MODULES}\""     >> "$TFVARS"

cat >> "$TFVARS" <<TFVARS

enable_scheduler    = ${ENABLE_SCHEDULER}
schedule_expression = "${SCHEDULE_EXPR}"
TFVARS
[[ -n "$NOTIFICATION_EMAIL" ]] && echo "notification_email = \"${NOTIFICATION_EMAIL}\"" >> "$TFVARS"

ok "terraform/terraform.tfvars written."
[[ -n "$ACCOUNT_CONTEXT" ]] && \
  { echo "export ASSESSMENT_CONTEXT=\"${ACCOUNT_CONTEXT}\"" > ./terraform/.deploy_env
    ok "Context saved to terraform/.deploy_env"; }

# ── Deploy ────────────────────────────────────────────────────────────────────
echo
DEPLOY_ARGS="--region ${AWS_REGION}"
$RUN_AFTER_DEPLOY && DEPLOY_ARGS="${DEPLOY_ARGS} --run"
info "Launching ./deploy.sh ${DEPLOY_ARGS}..."; echo; hr
bash ./deploy.sh $DEPLOY_ARGS
hr; echo; ok "AWS deployment complete."
echo
echo -e "  Useful commands:"
echo -e "    Logs:          ${CYAN}aws logs tail /aws/ecs/${NAME_PREFIX} --follow --region ${AWS_REGION}${RESET}"
echo -e "    Re-deploy:     ${CYAN}./deploy.sh --build-only --region ${AWS_REGION}${RESET}"
echo -e "    Trigger scan:  ${CYAN}./deploy.sh --run-only  --region ${AWS_REGION}${RESET}"
echo -e "    Destroy:       ${CYAN}./deploy.sh --destroy   --region ${AWS_REGION}${RESET}"
echo

# ── Cleanup ───────────────────────────────────────────────────────────────────
hr
echo -e "\n  ${BOLD}Cleanup${RESET}\n"
if confirm "Destroy all AWS infrastructure now? (ECS, ECR, S3, SSM — cannot be undone)"; then
  echo
  warn "Destroying all StratusAI AWS infrastructure..."
  bash ./deploy.sh --destroy --region "$AWS_REGION"
  ok "Infrastructure destroyed."
else
  info "Infrastructure left running. Destroy later with: ./deploy.sh --destroy --region ${AWS_REGION}"
fi
echo

# ═══════════════════════════════════════════════════════════════════════════════
# GCP DEPLOYMENT PATH
# ═══════════════════════════════════════════════════════════════════════════════
elif [[ "$PLATFORM" == "gcp" ]]; then

# ── GCP Step 2: Authentication ────────────────────────────────────────────────
section "2 — GCP authentication"

info "Checking gcloud auth..."
ACTIVE_ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -1)
if [[ -n "$ACTIVE_ACCOUNT" ]]; then
  ok "Logged in as: ${ACTIVE_ACCOUNT}"
else
  warn "No active gcloud account found."
  info "Running: gcloud auth login"
  gcloud auth login
  ACTIVE_ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -1)
  ok "Logged in as: ${ACTIVE_ACCOUNT}"
fi

echo
info "Checking Application Default Credentials (ADC)..."
if gcloud auth application-default print-access-token &>/dev/null; then
  ok "ADC are configured."
else
  warn "ADC not configured — required for Terraform."
  info "Running: gcloud auth application-default login"
  gcloud auth application-default login
fi

# ── GCP Step 3: Project & region ─────────────────────────────────────────────
section "3 — Project & region"

info "Fetching accessible GCP projects..."
PROJ_IDS=(); PROJ_LABELS=()
while IFS=$'\t' read -r pid pname; do
  [[ -z "$pid" ]] && continue
  PROJ_IDS+=("$pid")
  PROJ_LABELS+=("${pid}  —  ${pname}")
done < <(gcloud projects list --format="value(projectId,name)" 2>/dev/null | sort)

if [[ "${#PROJ_IDS[@]}" -gt 0 ]]; then
  PROJ_LABELS+=("Enter project ID manually")
  PROJ_CHOICE=$(ask_choice "GCP project to deploy INTO" "1" "${PROJ_LABELS[@]}")
  if (( PROJ_CHOICE <= ${#PROJ_IDS[@]} )); then
    GCP_PROJECT="${PROJ_IDS[$((PROJ_CHOICE - 1))]}"
    ok "Selected: ${GCP_PROJECT}"
  else
    GCP_PROJECT=$(ask "GCP project ID to deploy INTO")
    while [[ -z "$GCP_PROJECT" ]]; do
      err "Project ID is required."
      GCP_PROJECT=$(ask "GCP project ID to deploy INTO")
    done
  fi
else
  warn "Could not list projects — enter project ID manually."
  GCP_PROJECT=$(ask "GCP project ID to deploy INTO")
fi

GCP_REGION=$(ask  "GCP region" "us-central1")
NAME_PREFIX=$(ask "Resource name prefix" "stratusai")
ENVIRONMENT=$(ask "Environment label (prod / staging)" "prod")

info "Verifying project access..."
if gcloud projects describe "$GCP_PROJECT" &>/dev/null; then
  ok "Project ${GCP_PROJECT} is accessible."
else
  err "Cannot access project '${GCP_PROJECT}'. Check the ID and your permissions."
  exit 1
fi

# ── GCP Step 4: Scan target ───────────────────────────────────────────────────
section "4 — What to scan"

echo -e "  StratusAI will scan a GCP project."
echo -e "  It can scan the same project it's deployed into, or a different one."
echo
SCAN_PROJECT_CHOICE=$(ask_choice "Scan target" "1" \
  "Same project (${GCP_PROJECT})" \
  "Different project")

SCAN_PROJECT=""
if [[ "$SCAN_PROJECT_CHOICE" == "2" ]]; then
  echo
  if [[ "${#PROJ_IDS[@]}" -gt 0 ]]; then
    SCAN_CHOICE=$(ask_choice "Project to scan" "1" "${PROJ_LABELS[@]}")
    if (( SCAN_CHOICE <= ${#PROJ_IDS[@]} )); then
      SCAN_PROJECT="${PROJ_IDS[$((SCAN_CHOICE - 1))]}"
      ok "Scan target: ${SCAN_PROJECT}"
    else
      SCAN_PROJECT=$(ask "Project ID to scan")
    fi
  else
    SCAN_PROJECT=$(ask "Project ID to scan")
  fi
fi

# ── GCP Step 5: AI ────────────────────────────────────────────────────────────
section "5 — AI model & API key"

echo -e "    1) claude-sonnet-4-6          ${CYAN}Anthropic  ~\$0.08/scan  (recommended)${RESET}"
echo -e "    2) claude-haiku-4-5-20251001  ${CYAN}Anthropic  ~\$0.01/scan  (budget)${RESET}"
echo -e "    3) claude-opus-4-6            ${CYAN}Anthropic  ~\$0.30/scan  (best quality)${RESET}"
echo -e "    4) gpt-4o                     ${CYAN}OpenAI     ~\$0.10/scan${RESET}"
echo -e "    5) gemini-2.0-flash           ${CYAN}Google     ~\$0.005/scan (cheapest)${RESET}"
echo -e "    6) No AI                      ${CYAN}Free — raw scanner output only${RESET}"
echo
AI_CHOICE=$(ask_choice "Model" "1" \
  "claude-sonnet-4-6" "claude-haiku-4-5-20251001" "claude-opus-4-6" \
  "gpt-4o" "gemini-2.0-flash" "No AI")

ENABLE_AI="true"; AI_MODEL="claude-sonnet-4-6"; API_KEY=""
case "$AI_CHOICE" in
  1) AI_MODEL="claude-sonnet-4-6" ;;
  2) AI_MODEL="claude-haiku-4-5-20251001" ;;
  3) AI_MODEL="claude-opus-4-6" ;;
  4) AI_MODEL="gpt-4o" ;;
  5) AI_MODEL="gemini-2.0-flash" ;;
  6) ENABLE_AI="false" ;;
esac

if [[ "$ENABLE_AI" == "true" ]]; then
  echo
  case "$AI_MODEL" in
    claude-*) ENV_KEY="${ANTHROPIC_API_KEY:-}"; KEY_PREFIX="sk-ant-" ;;
    gpt-*)    ENV_KEY="${OPENAI_API_KEY:-}";    KEY_PREFIX="sk-" ;;
    gemini-*) ENV_KEY="${GOOGLE_API_KEY:-}";    KEY_PREFIX="AIza" ;;
  esac
  if [[ -n "$ENV_KEY" ]]; then
    ok "API key found in environment (${ENV_KEY:0:10}...)"
    API_KEY="$ENV_KEY"
  else
    API_KEY=$(ask_secret "API key")
  fi
  [[ "$API_KEY" != ${KEY_PREFIX}* ]] && \
    warn "Key prefix doesn't match '${KEY_PREFIX}...' — double-check."
fi

# ── GCP Step 6: Scan config ───────────────────────────────────────────────────
section "6 — Scan configuration"

echo -e "  Minimum severity filter:"
SEV_CHOICE=$(ask_choice "Severity" "1" \
  "INFO (everything)" "LOW" "MEDIUM (recommended)" "HIGH" "CRITICAL (only showstoppers)")
case "$SEV_CHOICE" in
  1) SEVERITY="INFO" ;; 2) SEVERITY="LOW" ;; 3) SEVERITY="MEDIUM" ;;
  4) SEVERITY="HIGH" ;; 5) SEVERITY="CRITICAL" ;; *) SEVERITY="INFO" ;;
esac

echo
ENABLE_EXTERNAL="false"; EXTERNAL_TARGET=""
if confirm "Enable external scan (ports, SSL, headers, DNS)?"; then
  ENABLE_EXTERNAL="true"
  EXTERNAL_TARGET=$(ask "Hostname or IP to scan (e.g. api.example.com)")
fi

echo
SCAN_MODULES=$(ask "Modules to run (comma-separated, Enter = all)" "")
echo
ACCOUNT_CONTEXT=$(ask "Environment context for AI (e.g. 'Production SaaS, GDPR scope')" "")

# ── GCP Step 7: Scheduler ─────────────────────────────────────────────────────
section "7 — Scheduled scans (optional)"

ENABLE_SCHEDULER="false"; SCHEDULE_EXPR="0 8 * * 1"; NOTIFICATION_EMAIL=""
if confirm "Enable automatic scheduled scans via Cloud Scheduler?"; then
  ENABLE_SCHEDULER="true"
  echo
  echo -e "  Cron syntax (UTC). Examples:"
  echo -e "    0 8 * * 1    — every Monday at 08:00"
  echo -e "    0 8 * * *    — every day at 08:00"
  echo -e "    0 */6 * * *  — every 6 hours"
  SCHEDULE_EXPR=$(ask "Cron expression" "0 8 * * 1")
  NOTIFICATION_EMAIL=$(ask "Alert email (leave blank to skip)" "")
fi

# ── GCP Step 8: Run on deploy? ────────────────────────────────────────────────
section "8 — Post-deploy"

RUN_AFTER_DEPLOY=false
confirm "Trigger a scan immediately after deployment?" && RUN_AFTER_DEPLOY=true

# ── GCP Summary ───────────────────────────────────────────────────────────────
echo; hr
echo -e "  ${BOLD}GCP Deployment Summary${RESET}"; hr; echo
printf "  %-28s %s\n" "Deploy to project:" "$GCP_PROJECT"
printf "  %-28s %s\n" "Scan project:"      "${SCAN_PROJECT:-$GCP_PROJECT (same)}"
printf "  %-28s %s\n" "Region:"            "$GCP_REGION"
printf "  %-28s %s\n" "Name prefix:"       "$NAME_PREFIX"
printf "  %-28s %s\n" "Environment:"       "$ENVIRONMENT"
echo
printf "  %-28s %s\n" "AI enabled:"        "$ENABLE_AI"
[[ "$ENABLE_AI" == "true" ]] && printf "  %-28s %s\n" "AI model:" "$AI_MODEL"
[[ -n "$API_KEY" ]]          && printf "  %-28s %s\n" "API key:" "${API_KEY:0:10}..."
echo
printf "  %-28s %s\n" "Severity filter:"   "$SEVERITY"
printf "  %-28s %s\n" "External scan:"     "$ENABLE_EXTERNAL"
[[ -n "$EXTERNAL_TARGET" ]] && printf "  %-28s %s\n" "External target:" "$EXTERNAL_TARGET"
[[ -n "$SCAN_MODULES" ]]    && printf "  %-28s %s\n" "Modules:" "$SCAN_MODULES"
[[ -n "$ACCOUNT_CONTEXT" ]] && printf "  %-28s %s\n" "AI context:" "$ACCOUNT_CONTEXT"
echo
printf "  %-28s %s\n" "Scheduled scans:"   "$ENABLE_SCHEDULER"
[[ "$ENABLE_SCHEDULER" == "true" ]] && printf "  %-28s %s\n" "Schedule:" "$SCHEDULE_EXPR"
[[ -n "$NOTIFICATION_EMAIL" ]]      && printf "  %-28s %s\n" "Alert email:" "$NOTIFICATION_EMAIL"
echo
printf "  %-28s %s\n" "Run scan on deploy:" "$RUN_AFTER_DEPLOY"
echo; hr; echo

confirm "Write terraform/gcp/terraform.tfvars and deploy?" || { info "Cancelled."; exit 0; }

# ── Write GCP tfvars ──────────────────────────────────────────────────────────
TFVARS="./terraform/gcp/terraform.tfvars"
info "Writing ${TFVARS}..."

cat > "$TFVARS" <<TFVARS
# Generated by deploy_wizard.sh — $(date -u +"%Y-%m-%dT%H:%M:%SZ")

gcp_project  = "${GCP_PROJECT}"
gcp_region   = "${GCP_REGION}"
name_prefix  = "${NAME_PREFIX}"
environment  = "${ENVIRONMENT}"
TFVARS

[[ -n "$SCAN_PROJECT" ]] && echo "scan_project = \"${SCAN_PROJECT}\"" >> "$TFVARS"

cat >> "$TFVARS" <<TFVARS

enable_ai = ${ENABLE_AI}
ai_model  = "${AI_MODEL}"
TFVARS
[[ -n "$API_KEY" ]] && echo "api_key   = \"${API_KEY}\"" >> "$TFVARS"

cat >> "$TFVARS" <<TFVARS

scan_severity        = "${SEVERITY}"
enable_external_scan = ${ENABLE_EXTERNAL}
TFVARS
[[ -n "$EXTERNAL_TARGET" ]] && echo "external_scan_target = \"${EXTERNAL_TARGET}\"" >> "$TFVARS"
[[ -n "$SCAN_MODULES" ]]    && echo "scan_modules         = \"${SCAN_MODULES}\""     >> "$TFVARS"

cat >> "$TFVARS" <<TFVARS

enable_scheduler    = ${ENABLE_SCHEDULER}
schedule_expression = "${SCHEDULE_EXPR}"
TFVARS
[[ -n "$NOTIFICATION_EMAIL" ]] && echo "notification_email = \"${NOTIFICATION_EMAIL}\"" >> "$TFVARS"

ok "terraform/gcp/terraform.tfvars written."
[[ -n "$ACCOUNT_CONTEXT" ]] && \
  { echo "export ASSESSMENT_CONTEXT=\"${ACCOUNT_CONTEXT}\"" > ./terraform/gcp/.deploy_env
    ok "Context saved to terraform/gcp/.deploy_env"; }

# ── Terraform init ────────────────────────────────────────────────────────────
echo
info "Initializing Terraform..."
terraform -chdir=./terraform/gcp init -upgrade -input=false

# ── Phase 1: Enable APIs + create Artifact Registry only ─────────────────────
# Cloud Run Job creation requires the image to already exist in the registry.
# So we create the registry first, push the image, then apply everything else.
# Note: we do NOT use a saved plan here — Phase 1 changes state, which would
# make any pre-generated plan stale before Phase 2 runs.
echo
info "Phase 1/2 — Enabling APIs and creating Artifact Registry..."
terraform -chdir=./terraform/gcp apply -input=false -auto-approve \
  -target=google_project_service.apis \
  -target=google_artifact_registry_repository.images
ok "Registry ready."

# ── Build + push image ────────────────────────────────────────────────────────
REGISTRY="${GCP_REGION}-docker.pkg.dev"
IMAGE_PATH="${REGISTRY}/${GCP_PROJECT}/${NAME_PREFIX}/${NAME_PREFIX}:latest"

echo
info "Configuring Docker auth for Artifact Registry..."
gcloud auth configure-docker "$REGISTRY" --quiet

echo
info "Building Docker image..."
docker build -t stratusai:build .

echo
info "Tagging + pushing to Artifact Registry..."
docker tag stratusai:build "$IMAGE_PATH"
docker push "$IMAGE_PATH"
ok "Image pushed: ${IMAGE_PATH}"

# ── Phase 2: Apply remaining infrastructure (Cloud Run Job, IAM, GCS, etc.) ──
echo
info "Phase 2/2 — Deploying remaining infrastructure..."
terraform -chdir=./terraform/gcp apply -input=false -auto-approve
ok "Infrastructure deployed."

# ── Get outputs ───────────────────────────────────────────────────────────────
JOB_NAME=$(terraform -chdir=./terraform/gcp output -raw cloud_run_job_name 2>/dev/null || echo "${NAME_PREFIX}-scan")
BUCKET=$(terraform -chdir=./terraform/gcp output -raw reports_bucket 2>/dev/null || echo "")
RUN_CMD=$(terraform -chdir=./terraform/gcp output -raw run_command 2>/dev/null || \
  echo "gcloud run jobs execute ${JOB_NAME} --region ${GCP_REGION} --project ${GCP_PROJECT}")

# ── Trigger scan ──────────────────────────────────────────────────────────────
if $RUN_AFTER_DEPLOY; then
  echo
  info "Triggering Cloud Run Job..."
  gcloud run jobs execute "$JOB_NAME" \
    --region "$GCP_REGION" \
    --project "$GCP_PROJECT" \
    --wait
  ok "Scan completed."
fi

hr; echo; ok "GCP deployment complete."
echo
echo -e "  Resources:"
echo -e "    Image:    ${CYAN}${IMAGE_PATH}${RESET}"
[[ -n "$BUCKET" ]] && echo -e "    Reports:  ${CYAN}gs://${BUCKET}/reports/${RESET}"
echo
echo -e "  Useful commands:"
echo -e "    Trigger scan:  ${CYAN}${RUN_CMD}${RESET}"
echo -e "    View logs:     ${CYAN}gcloud logging read 'resource.type=cloud_run_job AND resource.labels.job_name=${JOB_NAME}' --project ${GCP_PROJECT} --limit 50${RESET}"
echo -e "    Re-deploy:     ${CYAN}docker build -t ${IMAGE_PATH} . && docker push ${IMAGE_PATH}${RESET}"
echo -e "    Destroy:       ${CYAN}terraform -chdir=./terraform/gcp destroy${RESET}"
echo

# ── Cleanup ───────────────────────────────────────────────────────────────────
hr
echo -e "\n  ${BOLD}Cleanup${RESET}\n"
if confirm "Destroy all GCP infrastructure now? (Cloud Run, Artifact Registry, GCS, Secret Manager — cannot be undone)"; then
  echo
  warn "Destroying all StratusAI GCP infrastructure..."
  terraform -chdir=./terraform/gcp destroy -auto-approve
  ok "Infrastructure destroyed."

  if confirm "Also delete the local Docker image (stratusai:build)?"; then
    docker rmi stratusai:build 2>/dev/null && ok "Local image removed." || true
  fi
else
  info "Infrastructure left running. Destroy later with: terraform -chdir=./terraform/gcp destroy"
fi
echo

fi  # end GCP path
