#!/usr/bin/env bash
# StratusAI — Deployment Wizard
# Interactively collects all deployment parameters, verifies AWS auth,
# writes terraform/terraform.tfvars, and calls deploy.sh.
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
  echo -en "  ${BOLD}${prompt}${display_default}: ${RESET}"
  read -r reply
  echo "${reply:-$default}"
}

ask_secret() {
  local prompt="$1"
  echo -en "  ${BOLD}${prompt} (hidden): ${RESET}"
  read -rs reply; echo
  echo "$reply"
}

ask_choice() {
  # ask_choice "Prompt" "default_num" "opt1" "opt2" ...
  local prompt="$1" default="$2"; shift 2
  local opts=("$@") i=1
  for opt in "${opts[@]}"; do
    if [[ "$i" == "$default" ]]; then
      echo -e "    ${GREEN}${i}) ${opt}${RESET}"
    else
      echo -e "    ${i}) ${opt}"
    fi
    ((i++))
  done
  echo -en "  ${BOLD}${prompt} [${default}]: ${RESET}"
  read -r reply
  reply="${reply:-$default}"
  echo "$reply"
}

confirm() {
  local prompt="${1:-Continue?}"
  echo -en "  ${BOLD}${prompt} [y/N]: ${RESET}"
  read -r reply
  [[ "${reply,,}" == "y" || "${reply,,}" == "yes" ]]
}

# ── Header ────────────────────────────────────────────────────────────────────
clear
echo
hr
echo -e "  ${BOLD}${MAGENTA}StratusAI — Deployment Wizard${RESET}"
echo -e "  Deploy StratusAI to AWS (ECS Fargate + ECR + S3 + SSM)"
hr
echo
echo -e "  This wizard will:"
echo -e "    1. Verify your AWS credentials"
echo -e "    2. Collect deployment configuration"
echo -e "    3. Write ${CYAN}terraform/terraform.tfvars${RESET}"
echo -e "    4. Run ${CYAN}./deploy.sh${RESET} to provision infrastructure + push image"
echo

# ── Step 0: Check dependencies ────────────────────────────────────────────────
section "0 — Checking dependencies"

MISSING=()
for cmd in aws docker terraform; do
  if command -v "$cmd" &>/dev/null; then
    ok "$cmd found ($(command -v "$cmd"))"
  else
    err "$cmd not found"
    MISSING+=("$cmd")
  fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo
  warn "Install missing tools before deploying:"
  [[ " ${MISSING[*]} " == *" aws "* ]]        && info "  aws:       https://aws.amazon.com/cli/"
  [[ " ${MISSING[*]} " == *" docker "* ]]     && info "  docker:    https://docs.docker.com/get-docker/"
  [[ " ${MISSING[*]} " == *" terraform "* ]]  && info "  terraform: https://developer.hashicorp.com/terraform/install"
  exit 1
fi

# ── Step 1: AWS Authentication ────────────────────────────────────────────────
section "1 — AWS Authentication"

AWS_PROFILE_ARG=""
echo -e "  Available AWS profiles:"
if aws configure list-profiles 2>/dev/null | head -10 | while read -r p; do echo "    • $p"; done; then
  true
else
  info "(no profiles found — using environment credentials)"
fi
echo

AWS_PROFILE=$(ask "AWS profile" "default")
[[ -n "$AWS_PROFILE" && "$AWS_PROFILE" != "default" ]] && export AWS_PROFILE && AWS_PROFILE_ARG="--profile $AWS_PROFILE"

echo
info "Verifying credentials..."
if CALLER=$(aws sts get-caller-identity $AWS_PROFILE_ARG --output json 2>/dev/null); then
  ACCOUNT_ID=$(echo "$CALLER" | grep -o '"Account": "[^"]*"' | cut -d'"' -f4)
  CALLER_ARN=$(echo "$CALLER" | grep -o '"Arn": "[^"]*"' | cut -d'"' -f4)
  ok "Authenticated as: ${CALLER_ARN}"
  ok "Account ID:       ${ACCOUNT_ID}"
else
  err "AWS authentication failed."
  warn "Run 'aws configure' or set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY."
  exit 1
fi

# ── Step 2: Deployment Basics ─────────────────────────────────────────────────
section "2 — Deployment basics"

AWS_REGION=$(ask "AWS region" "us-east-1")
NAME_PREFIX=$(ask "Resource name prefix" "stratusai")
ENVIRONMENT=$(ask "Environment label (e.g. prod, staging)" "prod")

# ── Step 3: Networking ────────────────────────────────────────────────────────
section "3 — Networking (VPC & Subnets)"

echo -e "  StratusAI runs as an ECS Fargate task and needs a VPC + subnet."
echo -e "  You can use an existing VPC or let Terraform create a new one."
echo

echo -e "    1) Create a new VPC (simplest)"
echo -e "    2) Use an existing VPC"
NET_CHOICE=$(ask_choice "Choice" "1" "Create new VPC" "Use existing VPC")

VPC_ID=""
SUBNET_IDS=""

if [[ "$NET_CHOICE" == "2" ]]; then
  echo
  info "Fetching VPCs in ${AWS_REGION}..."
  aws ec2 describe-vpcs $AWS_PROFILE_ARG --region "$AWS_REGION" \
    --query 'Vpcs[*].[VpcId,CidrBlock,Tags[?Key==`Name`].Value|[0]]' \
    --output text 2>/dev/null | while IFS=$'\t' read -r id cidr name; do
      echo "    ${id}  ${cidr}  ${name:-<no name>}"
    done || warn "Could not list VPCs — enter ID manually."
  echo
  VPC_ID=$(ask "VPC ID (e.g. vpc-0abc1234)")

  echo
  info "Fetching subnets for ${VPC_ID}..."
  aws ec2 describe-subnets $AWS_PROFILE_ARG --region "$AWS_REGION" \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
    --query 'Subnets[*].[SubnetId,AvailabilityZone,CidrBlock,Tags[?Key==`Name`].Value|[0]]' \
    --output text 2>/dev/null | while IFS=$'\t' read -r id az cidr name; do
      echo "    ${id}  ${az}  ${cidr}  ${name:-<no name>}"
    done || warn "Could not list subnets."
  echo
  SUBNET_IDS=$(ask "Subnet IDs (comma-separated, e.g. subnet-aaa,subnet-bbb)")
fi

# ── Step 4: AI Configuration ──────────────────────────────────────────────────
section "4 — AI configuration"

echo -e "    1) claude-sonnet-4-6   ${CYAN}(recommended — best quality, ~\$0.08/scan)${RESET}"
echo -e "    2) claude-haiku-4-5-20251001    ${CYAN}(fast + cheap, ~\$0.01/scan)${RESET}"
echo -e "    3) claude-opus-4-6     ${CYAN}(most capable, ~\$0.30/scan)${RESET}"
echo -e "    4) gpt-4o              ${CYAN}(OpenAI — ~\$0.10/scan, needs OPENAI_API_KEY)${RESET}"
echo -e "    5) gemini-2.0-flash    ${CYAN}(Google — ~\$0.005/scan, needs GOOGLE_API_KEY)${RESET}"
echo -e "    6) Disable AI          ${CYAN}(raw scanner output only, free)${RESET}"
echo
MODEL_CHOICE=$(ask_choice "Model" "1" \
  "claude-sonnet-4-6" "claude-haiku-4-5-20251001" "claude-opus-4-6" \
  "gpt-4o" "gemini-2.0-flash" "Disable AI")

ENABLE_AI="true"
AI_MODEL="claude-sonnet-4-6"
API_KEY=""
API_KEY_PROVIDER=""

case "$MODEL_CHOICE" in
  1) AI_MODEL="claude-sonnet-4-6";          API_KEY_PROVIDER="anthropic" ;;
  2) AI_MODEL="claude-haiku-4-5-20251001";  API_KEY_PROVIDER="anthropic" ;;
  3) AI_MODEL="claude-opus-4-6";            API_KEY_PROVIDER="anthropic" ;;
  4) AI_MODEL="gpt-4o";                     API_KEY_PROVIDER="openai"    ;;
  5) AI_MODEL="gemini-2.0-flash";           API_KEY_PROVIDER="google"    ;;
  6) ENABLE_AI="false";                     API_KEY_PROVIDER="none"      ;;
esac

if [[ "$ENABLE_AI" == "true" ]]; then
  echo
  case "$API_KEY_PROVIDER" in
    anthropic)
      ENV_KEY="${ANTHROPIC_API_KEY:-}"
      if [[ -n "$ENV_KEY" ]]; then
        ok "ANTHROPIC_API_KEY found in environment (${ENV_KEY:0:10}...)"
        API_KEY="$ENV_KEY"
      else
        API_KEY=$(ask_secret "Anthropic API key (sk-ant-...)")
      fi
      if [[ "$API_KEY" != sk-ant-* ]]; then
        warn "Key doesn't look like an Anthropic key (expected sk-ant-...)"
      fi
      ;;
    openai)
      ENV_KEY="${OPENAI_API_KEY:-}"
      if [[ -n "$ENV_KEY" ]]; then
        ok "OPENAI_API_KEY found in environment"
        API_KEY="$ENV_KEY"
      else
        API_KEY=$(ask_secret "OpenAI API key (sk-...)")
      fi
      warn "Note: Terraform stores the key in SSM as 'anthropic_api_key' variable name."
      warn "The CLI will read it correctly — model=${AI_MODEL} routes to OpenAI automatically."
      ;;
    google)
      ENV_KEY="${GOOGLE_API_KEY:-}"
      if [[ -n "$ENV_KEY" ]]; then
        ok "GOOGLE_API_KEY found in environment"
        API_KEY="$ENV_KEY"
      else
        API_KEY=$(ask_secret "Google API key (AIza...)")
      fi
      ;;
  esac
fi

# ── Step 5: Scan Configuration ────────────────────────────────────────────────
section "5 — Scan configuration"

SCAN_REGIONS=$(ask "AWS regions to scan (comma-separated)" "$AWS_REGION")

echo
echo -e "  Minimum severity to include in reports:"
echo -e "    1) INFO     — everything"
echo -e "    2) LOW"
echo -e "    3) MEDIUM   — recommended"
echo -e "    4) HIGH"
echo -e "    5) CRITICAL — only showstoppers"
SEV_CHOICE=$(ask_choice "Severity" "1" INFO LOW MEDIUM HIGH CRITICAL)
SEVERITY=""
case "$SEV_CHOICE" in
  1) SEVERITY="INFO"     ;;
  2) SEVERITY="LOW"      ;;
  3) SEVERITY="MEDIUM"   ;;
  4) SEVERITY="HIGH"     ;;
  5) SEVERITY="CRITICAL" ;;
  *) SEVERITY="INFO"     ;;
esac

echo
ENABLE_EXTERNAL="false"
EXTERNAL_TARGET=""
if confirm "Enable external scan (ports, SSL, headers, DNS) against a public hostname?"; then
  ENABLE_EXTERNAL="true"
  EXTERNAL_TARGET=$(ask "Hostname or IP to scan externally (e.g. api.example.com)")
fi

echo
SCAN_MODULES=$(ask "Modules to run (comma-separated, or Enter for all)" "")

echo
ACCOUNT_CONTEXT=$(ask "Environment context for AI (e.g. 'Production fintech, PCI DSS')" "")

# ── Step 6: Scheduler ─────────────────────────────────────────────────────────
section "6 — Scheduled scans (optional)"

echo -e "  StratusAI can run automatically on a schedule via EventBridge."
echo

ENABLE_SCHEDULER="false"
SCHEDULE_EXPR="rate(7 days)"
NOTIFICATION_EMAIL=""

if confirm "Enable scheduled automatic scans?"; then
  ENABLE_SCHEDULER="true"
  echo
  echo -e "  Schedule examples:"
  echo -e "    rate(7 days)          — weekly"
  echo -e "    rate(1 day)           — daily"
  echo -e "    cron(0 8 * * ? *)     — every day at 08:00 UTC"
  echo -e "    cron(0 8 ? * MON *)   — every Monday at 08:00 UTC"
  echo
  SCHEDULE_EXPR=$(ask "Schedule expression" "rate(7 days)")
  NOTIFICATION_EMAIL=$(ask "Email for scan completion alerts (leave blank to skip)" "")
fi

# ── Step 7: Deployment options ────────────────────────────────────────────────
section "7 — Deployment options"

RUN_AFTER_DEPLOY=false
if confirm "Trigger a scan immediately after deployment?"; then
  RUN_AFTER_DEPLOY=true
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo
hr
echo -e "  ${BOLD}Configuration Summary${RESET}"
hr
echo
printf "  %-26s %s\n" "AWS Account:"        "$ACCOUNT_ID"
printf "  %-26s %s\n" "Region:"             "$AWS_REGION"
printf "  %-26s %s\n" "Name prefix:"        "$NAME_PREFIX"
printf "  %-26s %s\n" "Environment:"        "$ENVIRONMENT"
echo
if [[ -n "$VPC_ID" ]]; then
  printf "  %-26s %s\n" "VPC:"              "$VPC_ID"
  printf "  %-26s %s\n" "Subnets:"          "$SUBNET_IDS"
else
  printf "  %-26s %s\n" "VPC:"              "New VPC (created by Terraform)"
fi
echo
printf "  %-26s %s\n" "AI enabled:"         "$ENABLE_AI"
[[ "$ENABLE_AI" == "true" ]] && printf "  %-26s %s\n" "AI model:"   "$AI_MODEL"
[[ -n "$API_KEY" ]]          && printf "  %-26s %s\n" "API key:"    "${API_KEY:0:10}..."
echo
printf "  %-26s %s\n" "Scan regions:"       "$SCAN_REGIONS"
printf "  %-26s %s\n" "Severity filter:"    "$SEVERITY"
printf "  %-26s %s\n" "External scan:"      "$ENABLE_EXTERNAL"
[[ -n "$EXTERNAL_TARGET" ]]  && printf "  %-26s %s\n" "External target:" "$EXTERNAL_TARGET"
[[ -n "$SCAN_MODULES" ]]     && printf "  %-26s %s\n" "Modules:"    "$SCAN_MODULES"
[[ -n "$ACCOUNT_CONTEXT" ]]  && printf "  %-26s %s\n" "AI context:" "$ACCOUNT_CONTEXT"
echo
printf "  %-26s %s\n" "Scheduled scans:"    "$ENABLE_SCHEDULER"
[[ "$ENABLE_SCHEDULER" == "true" ]] && printf "  %-26s %s\n" "Schedule:" "$SCHEDULE_EXPR"
[[ -n "$NOTIFICATION_EMAIL" ]]      && printf "  %-26s %s\n" "Alert email:" "$NOTIFICATION_EMAIL"
echo
printf "  %-26s %s\n" "Run scan on deploy:" "$RUN_AFTER_DEPLOY"
echo
hr
echo

if ! confirm "Write terraform.tfvars and deploy?"; then
  info "Deployment cancelled. Run ./deploy_wizard.sh again to restart."
  exit 0
fi

# ── Write terraform.tfvars ────────────────────────────────────────────────────
TFVARS_FILE="./terraform/terraform.tfvars"
echo
info "Writing ${TFVARS_FILE}..."

cat > "$TFVARS_FILE" <<TFVARS
# Generated by deploy_wizard.sh — $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Re-run ./deploy_wizard.sh to regenerate.

aws_region   = "${AWS_REGION}"
name_prefix  = "${NAME_PREFIX}"
environment  = "${ENVIRONMENT}"

TFVARS

# Networking
if [[ -n "$VPC_ID" ]]; then
  echo "vpc_id     = \"${VPC_ID}\"" >> "$TFVARS_FILE"
  # Convert comma-separated to HCL list
  HCL_SUBNETS=$(echo "$SUBNET_IDS" | sed 's/[[:space:]]//g' | sed 's/,/", "/g')
  echo "subnet_ids = [\"${HCL_SUBNETS}\"]" >> "$TFVARS_FILE"
fi

cat >> "$TFVARS_FILE" <<TFVARS

# AI
enable_ai    = ${ENABLE_AI}
claude_model = "${AI_MODEL}"
TFVARS

if [[ -n "$API_KEY" ]]; then
  echo "anthropic_api_key = \"${API_KEY}\"" >> "$TFVARS_FILE"
fi

cat >> "$TFVARS_FILE" <<TFVARS

# Scan
scan_regions          = "${SCAN_REGIONS}"
scan_severity         = "${SEVERITY}"
enable_external_scan  = ${ENABLE_EXTERNAL}
TFVARS

[[ -n "$EXTERNAL_TARGET" ]] && echo "external_scan_target = \"${EXTERNAL_TARGET}\"" >> "$TFVARS_FILE"
[[ -n "$SCAN_MODULES" ]]    && echo "scan_modules         = \"${SCAN_MODULES}\""     >> "$TFVARS_FILE"

cat >> "$TFVARS_FILE" <<TFVARS

# Scheduler
enable_scheduler    = ${ENABLE_SCHEDULER}
schedule_expression = "${SCHEDULE_EXPR}"
TFVARS

[[ -n "$NOTIFICATION_EMAIL" ]] && echo "notification_email = \"${NOTIFICATION_EMAIL}\"" >> "$TFVARS_FILE"

ok "terraform.tfvars written."

# Write context to a separate env file (not in tfvars — it's a CLI arg, not a TF var)
if [[ -n "$ACCOUNT_CONTEXT" ]]; then
  echo "export ASSESSMENT_CONTEXT=\"${ACCOUNT_CONTEXT}\"" > ./terraform/.deploy_env
  ok "Assessment context saved to ./terraform/.deploy_env"
fi

# ── Run deploy.sh ─────────────────────────────────────────────────────────────
echo
DEPLOY_ARGS="--region ${AWS_REGION}"
$RUN_AFTER_DEPLOY && DEPLOY_ARGS="${DEPLOY_ARGS} --run"

info "Launching ./deploy.sh ${DEPLOY_ARGS} ..."
echo
hr

bash ./deploy.sh $DEPLOY_ARGS

hr
echo
ok "Deployment wizard complete."
echo
echo -e "  Useful commands:"
echo -e "    View logs:     ${CYAN}aws logs tail /aws/ecs/${NAME_PREFIX} --follow --region ${AWS_REGION}${RESET}"
echo -e "    Re-deploy:     ${CYAN}./deploy.sh --build-only --region ${AWS_REGION}${RESET}"
echo -e "    Trigger scan:  ${CYAN}./deploy.sh --run-only  --region ${AWS_REGION}${RESET}"
echo -e "    Destroy all:   ${CYAN}./deploy.sh --destroy   --region ${AWS_REGION}${RESET}"
echo -e "    Edit config:   ${CYAN}${TFVARS_FILE}${RESET}"
echo
