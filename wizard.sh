#!/usr/bin/env bash
# =============================================================================
# StratusAI Wizard — Interactive setup and launch
# =============================================================================
# Walks you through every configuration option and runs the tool.
# Supports Docker (default) or local Python execution.
#
# Usage:
#   bash wizard.sh
# =============================================================================
set -euo pipefail

# ─── Colors & helpers ─────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info()    { echo -e "${CYAN}  ▸${NC} $*"; }
ok()      { echo -e "${GREEN}  ✓${NC} $*"; }
warn()    { echo -e "${YELLOW}  !${NC} $*"; }
err()     { echo -e "${RED}  ✗${NC} $*"; }
section() { echo -e "\n${BOLD}${BLUE}┌─  $*${NC}\n"; }
hr()      { echo -e "${DIM}  ────────────────────────────────────────────────${NC}"; }

ask() {
  # ask <var_name> <prompt> [default]
  local varname="$1" prompt="$2" default="${3:-}"
  local display_default=""
  [[ -n "$default" ]] && display_default=" ${DIM}[${default}]${NC}"
  echo -en "  ${BOLD}${prompt}${NC}${display_default}: "
  read -r value
  value="${value:-$default}"
  printf -v "$varname" '%s' "$value"
}

ask_secret() {
  # ask_secret <var_name> <prompt>
  local varname="$1" prompt="$2"
  echo -en "  ${BOLD}${prompt}${NC}: "
  read -rs value
  echo ""
  printf -v "$varname" '%s' "$value"
}

ask_choice() {
  # ask_choice <var_name> <prompt> <options...>
  local varname="$1" prompt="$2"; shift 2
  local options=("$@")
  echo -e "  ${BOLD}${prompt}${NC}"
  local i=1
  for opt in "${options[@]}"; do
    echo -e "    ${CYAN}${i})${NC} ${opt}"
    ((i++))
  done
  echo -en "  ${BOLD}Choice${NC} ${DIM}[1]${NC}: "
  read -r choice
  choice="${choice:-1}"
  printf -v "$varname" '%s' "${options[$((choice-1))]}"
}

confirm() {
  # confirm <prompt> → returns 0 for yes
  echo -en "  ${BOLD}$1${NC} ${DIM}[y/N]${NC}: "
  read -r ans
  [[ "${ans:-}" =~ ^[Yy]$ ]]
}

# =============================================================================
# Banner
# =============================================================================
clear
echo -e "${BOLD}${CYAN}"
cat <<'BANNER'
  ╔══════════════════════════════════════════════════════════╗
  ║                                                          ║
  ║   ███████╗████████╗██████╗  █████╗ ████████╗██╗   ██╗  ║
  ║   ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗╚══██╔══╝██║   ██║  ║
  ║   ███████╗   ██║   ██████╔╝███████║   ██║   ██║   ██║  ║
  ║   ╚════██║   ██║   ██╔══██╗██╔══██║   ██║   ██║   ██║  ║
  ║   ███████║   ██║   ██║  ██║██║  ██║   ██║   ╚██████╔╝  ║
  ║   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝   ║
  ║                                                          ║
  ║          AI-Powered Cloud Security Assessment            ║
  ║                    Setup Wizard                          ║
  ╚══════════════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"
echo -e "  This wizard will guide you through all configuration options"
echo -e "  and launch StratusAI. Takes about ${BOLD}2 minutes${NC} to configure.\n"

# =============================================================================
# Step 1: Execution mode (Docker or local Python)
# =============================================================================
section "Step 1 of 7 — Execution Mode"

RUN_MODE=""
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
  ok "Docker detected"
  if [[ -d "${SCRIPT_DIR}" ]] && [[ -f "${SCRIPT_DIR}/Dockerfile" ]]; then
    ask_choice RUN_MODE "How would you like to run StratusAI?" \
      "Docker (recommended — no local dependencies needed)" \
      "Local Python (requires pip install -r requirements.txt)"
  else
    RUN_MODE="Local Python (requires pip install -r requirements.txt)"
    warn "Dockerfile not found — falling back to local Python"
  fi
else
  RUN_MODE="Local Python (requires pip install -r requirements.txt)"
  warn "Docker not available — using local Python"
fi

USE_DOCKER=false
[[ "${RUN_MODE}" == Docker* ]] && USE_DOCKER=true
ok "Execution: ${RUN_MODE%%(*}(${RUN_MODE#*(})"

if $USE_DOCKER; then
  info "Building Docker image (this takes ~60s the first time)..."
  docker build -q -t stratus-ai "${SCRIPT_DIR}" && ok "Docker image ready"
else
  if ! python3 -c "import assessment" &>/dev/null 2>&1; then
    warn "assessment package not installed. Run: pip install -r requirements.txt"
  fi
fi

# =============================================================================
# Step 2: Cloud Provider
# =============================================================================
section "Step 2 of 7 — Cloud Provider"

echo -e "  Which cloud environment do you want to assess?\n"
ask_choice PROVIDER "Cloud provider:" \
  "aws   — Amazon Web Services" \
  "gcp   — Google Cloud Platform" \
  "external — External-only scan (any host, no cloud API access)"

# Extract just the provider code
PROVIDER="${PROVIDER%% *}"
ok "Provider: ${PROVIDER}"

# =============================================================================
# Step 3: Scan Mode & Target
# =============================================================================
section "Step 3 of 7 — Scan Mode"

MODE=""
TARGET=""

if [[ "${PROVIDER}" == "external" ]]; then
  PROVIDER="aws"     # provider unused for external-only
  MODE="external"
  ask TARGET "Target hostname or IP (e.g. example.com or 1.2.3.4)" ""
  while [[ -z "${TARGET}" ]]; do
    err "Target is required for external mode."
    ask TARGET "Target hostname or IP" ""
  done
  ok "Mode: external → ${TARGET}"
else
  ask_choice MODE "Scan mode:" \
    "internal — Cloud API scanning only (IAM, storage, compute, ...)" \
    "external — Network scanning only (ports, TLS, headers, DNS)" \
    "both     — Internal + external (recommended)"
  MODE="${MODE%% *}"

  if [[ "${MODE}" != "internal" ]]; then
    ask TARGET "Target hostname or IP for external scan (press Enter to skip)" ""
    if [[ -z "${TARGET}" ]] && [[ "${MODE}" == "both" ]]; then
      warn "No target provided — switching to internal-only mode."
      MODE="internal"
    fi
  fi
  ok "Mode: ${MODE}${TARGET:+ → ${TARGET}}"
fi

# =============================================================================
# Step 4: Cloud Credentials
# =============================================================================
section "Step 4 of 7 — Cloud Credentials"

GCP_PROJECT=""
AWS_PROFILE=""
AWS_REGION=""
GCP_REGION=""

if [[ "${MODE}" != "external" ]]; then
  if [[ "${PROVIDER}" == "aws" ]]; then
    echo -e "  AWS credentials are read from your environment or ~/.aws/credentials.\n"

    # Check for existing credentials
    if aws sts get-caller-identity &>/dev/null 2>&1; then
      CURRENT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "unknown")
      CURRENT_ARN=$(aws sts get-caller-identity --query Arn --output text 2>/dev/null || echo "unknown")
      ok "Active AWS credentials detected"
      info "  Account: ${CURRENT_ACCOUNT}"
      info "  Identity: ${CURRENT_ARN}"
      ask AWS_PROFILE "AWS profile name (press Enter for current default)" ""
    else
      warn "No active AWS credentials found."
      echo -e "  Please configure credentials with one of:\n"
      echo -e "    ${DIM}export AWS_ACCESS_KEY_ID=...${NC}"
      echo -e "    ${DIM}export AWS_SECRET_ACCESS_KEY=...${NC}"
      echo -e "    ${DIM}aws configure${NC}\n"
      if ! confirm "Credentials configured? Continue?"; then
        echo "Exiting. Configure AWS credentials and re-run the wizard."
        exit 1
      fi
      ask AWS_PROFILE "AWS profile name (press Enter for default)" ""
    fi

    DEFAULT_REGION=$(aws configure get region 2>/dev/null || echo "us-east-1")
    ask AWS_REGION "AWS region" "${DEFAULT_REGION}"

  elif [[ "${PROVIDER}" == "gcp" ]]; then
    echo -e "  GCP uses Application Default Credentials (ADC).\n"

    if gcloud auth application-default print-access-token &>/dev/null 2>&1; then
      ok "GCP Application Default Credentials found"
    else
      warn "GCP ADC not configured."
      echo -e "  Run: ${DIM}gcloud auth application-default login${NC}\n"
      if ! confirm "Credentials configured? Continue?"; then
        echo "Exiting. Configure GCP credentials and re-run the wizard."
        exit 1
      fi
    fi

    DETECTED_PROJECT=$(gcloud config get-value project 2>/dev/null || echo "")
    ask GCP_PROJECT "GCP project ID" "${DETECTED_PROJECT}"
    while [[ -z "${GCP_PROJECT}" ]]; do
      err "GCP project ID is required."
      ask GCP_PROJECT "GCP project ID" ""
    done
    ask GCP_REGION "GCP region" "us-central1"
    ok "Project: ${GCP_PROJECT} (${GCP_REGION})"
  fi
fi

# =============================================================================
# Step 5: AI Model & API Key
# =============================================================================
section "Step 5 of 7 — AI Model"

echo -e "  Choose the AI model for security analysis.\n"
echo -e "  ${DIM}Cost comparison (per full scan):${NC}"
echo -e "    Gemini 2.0 Flash     ~\$0.01  (fastest, cheapest)"
echo -e "    Claude Haiku 4.5     ~\$0.01  (fast, cheap)"
echo -e "    GPT-4o mini          ~\$0.01  (fast, cheap)"
echo -e "    Claude Sonnet 4.6    ~\$0.06  (best quality, default)"
echo -e "    GPT-4o               ~\$0.06  (good quality)"
echo -e "    Claude Opus 4.6      ~\$0.30  (highest quality)"
echo -e "    o3-mini              ~\$0.05  (reasoning model)\n"

ask_choice AI_PROVIDER "AI provider:" \
  "Anthropic (Claude) — recommended" \
  "OpenAI (GPT-4o, o1, o3)" \
  "Google (Gemini)"

AI_KEY=""
MODEL=""

if [[ "${AI_PROVIDER}" == Anthropic* ]]; then
  ask_choice MODEL "Claude model:" \
    "claude-sonnet-4-6       — Best quality (default, \$0.06/scan)" \
    "claude-haiku-4-5-20251001 — Fast & cheap (\$0.01/scan)" \
    "claude-opus-4-6         — Highest quality (\$0.30/scan)"
  MODEL="${MODEL%%[[:space:]]*}"

  if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
    ok "ANTHROPIC_API_KEY already set in environment"
    AI_KEY="${ANTHROPIC_API_KEY}"
  else
    ask_secret AI_KEY "Anthropic API key (sk-ant-...)"
    while [[ ! "${AI_KEY}" =~ ^sk-ant- ]]; do
      err "Key should start with sk-ant-"
      ask_secret AI_KEY "Anthropic API key"
    done
  fi
  export ANTHROPIC_API_KEY="${AI_KEY}"

elif [[ "${AI_PROVIDER}" == OpenAI* ]]; then
  ask_choice MODEL "OpenAI model:" \
    "gpt-4o        — Best quality (\$0.06/scan)" \
    "gpt-4o-mini   — Fast & cheap (\$0.01/scan)" \
    "o3-mini       — Reasoning model (\$0.05/scan)" \
    "o1            — Advanced reasoning (\$0.25/scan)"
  MODEL="${MODEL%%[[:space:]]*}"

  if [[ -n "${OPENAI_API_KEY:-}" ]]; then
    ok "OPENAI_API_KEY already set in environment"
    AI_KEY="${OPENAI_API_KEY}"
  else
    ask_secret AI_KEY "OpenAI API key (sk-...)"
    while [[ ! "${AI_KEY}" =~ ^sk- ]]; do
      err "Key should start with sk-"
      ask_secret AI_KEY "OpenAI API key"
    done
  fi
  export OPENAI_API_KEY="${AI_KEY}"

elif [[ "${AI_PROVIDER}" == Google* ]]; then
  ask_choice MODEL "Gemini model:" \
    "gemini-2.0-flash  — Fastest & cheapest (\$0.01/scan)" \
    "gemini-1.5-pro    — Higher quality (\$0.05/scan)" \
    "gemini-1.5-flash  — Balanced (\$0.02/scan)"
  MODEL="${MODEL%%[[:space:]]*}"

  if [[ -n "${GOOGLE_API_KEY:-}" ]]; then
    ok "GOOGLE_API_KEY already set in environment"
  else
    echo -e "\n  ${DIM}You can use a Google API key or Application Default Credentials (ADC).${NC}"
    if confirm "Use Application Default Credentials (ADC) instead of API key?"; then
      ok "Using ADC for Gemini"
    else
      ask_secret AI_KEY "Google API key (AIza...)"
      export GOOGLE_API_KEY="${AI_KEY}"
    fi
  fi
fi

ok "Model: ${MODEL}"

# =============================================================================
# Step 6: Scan Options
# =============================================================================
section "Step 6 of 7 — Scan Options"

# Severity filter
ask_choice SEVERITY "Minimum severity to include in report:" \
  "INFO     — Show all findings (default)" \
  "LOW      — Skip info-only findings" \
  "MEDIUM   — Show Medium and above" \
  "HIGH     — Show High and Critical only" \
  "CRITICAL — Show Critical only"
SEVERITY="${SEVERITY%% *}"

# Modules
MODULES_FILTER=""
if [[ "${MODE}" != "external" ]]; then
  if confirm "Run all scanner modules? (No = choose specific modules)"; then
    MODULES_FILTER=""
    ok "Running all modules"
  else
    if [[ "${PROVIDER}" == "aws" ]]; then
      echo -e "\n  ${DIM}Available modules: iam, s3, ec2, cloudtrail, rds, lambda, kms, secretsmanager, eks${NC}"
    else
      echo -e "\n  ${DIM}Available modules: iam, compute, storage, cloudfunctions, cloudrun, secretmanager, logging${NC}"
    fi
    ask MODULES_FILTER "Comma-separated modules to run (e.g. iam,s3,ec2)" ""
  fi
fi

# Context
echo ""
info "The AI uses environment context to sharpen severity ratings."
info "Examples: 'Production fintech, PCI DSS scope' | 'Dev environment, no real data'"
ask CONTEXT "Environment context (press Enter to use default)" \
  "Production environment — assume sensitive data"

# Output directory
ask OUTPUT_DIR "Report output directory" "./output"

# =============================================================================
# Step 7: Review & Run
# =============================================================================
section "Step 7 of 7 — Review"

echo -e "  ${BOLD}Configuration summary:${NC}\n"
echo -e "  ${DIM}Provider:${NC}     ${PROVIDER^^}"
echo -e "  ${DIM}Mode:${NC}         ${MODE}"
[[ -n "${TARGET}" ]]       && echo -e "  ${DIM}Target:${NC}       ${TARGET}"
[[ -n "${GCP_PROJECT}" ]]  && echo -e "  ${DIM}GCP Project:${NC}  ${GCP_PROJECT} (${GCP_REGION})"
[[ -n "${AWS_REGION}" ]]   && echo -e "  ${DIM}Region:${NC}       ${AWS_REGION}"
[[ -n "${AWS_PROFILE}" ]]  && echo -e "  ${DIM}AWS Profile:${NC}  ${AWS_PROFILE}"
echo -e "  ${DIM}AI Model:${NC}     ${MODEL}"
echo -e "  ${DIM}Severity:${NC}     ${SEVERITY}+"
[[ -n "${MODULES_FILTER}" ]] && echo -e "  ${DIM}Modules:${NC}      ${MODULES_FILTER}"
echo -e "  ${DIM}Context:${NC}      ${CONTEXT}"
echo -e "  ${DIM}Output:${NC}       ${OUTPUT_DIR}"
echo -e "  ${DIM}Docker:${NC}       ${USE_DOCKER}"
echo ""
hr

if ! confirm "Launch StratusAI with these settings?"; then
  echo -e "\n  Cancelled. Re-run ${BOLD}bash wizard.sh${NC} to start over.\n"
  exit 0
fi

# =============================================================================
# Build & run the command
# =============================================================================
section "Launching StratusAI"

mkdir -p "${OUTPUT_DIR}"
ABS_OUTPUT="$(cd "${OUTPUT_DIR}" && pwd)"

# Assemble CLI args
CLI_ARGS=(
  --provider "${PROVIDER}"
  --mode "${MODE}"
  --model "${MODEL}"
  --severity "${SEVERITY}"
  --context "${CONTEXT}"
  --output-dir /app/output
)

[[ -n "${TARGET}" ]]         && CLI_ARGS+=(--target "${TARGET}")
[[ -n "${MODULES_FILTER}" ]] && CLI_ARGS+=(--modules "${MODULES_FILTER}")
[[ -n "${GCP_PROJECT}" ]]    && CLI_ARGS+=(--project "${GCP_PROJECT}")
[[ -n "${AWS_REGION}" ]]     && CLI_ARGS+=(--region "${AWS_REGION}")

if $USE_DOCKER; then
  # Build Docker run command
  DOCKER_RUN=(docker run --rm)

  # API keys
  [[ -n "${ANTHROPIC_API_KEY:-}" ]] && DOCKER_RUN+=(-e "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}")
  [[ -n "${OPENAI_API_KEY:-}" ]]    && DOCKER_RUN+=(-e "OPENAI_API_KEY=${OPENAI_API_KEY}")
  [[ -n "${GOOGLE_API_KEY:-}" ]]    && DOCKER_RUN+=(-e "GOOGLE_API_KEY=${GOOGLE_API_KEY}")

  # AWS credentials
  if [[ "${PROVIDER}" == "aws" ]] && [[ "${MODE}" != "external" ]]; then
    [[ -n "${AWS_ACCESS_KEY_ID:-}" ]]     && DOCKER_RUN+=(-e "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}")
    [[ -n "${AWS_SECRET_ACCESS_KEY:-}" ]] && DOCKER_RUN+=(-e "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}")
    [[ -n "${AWS_SESSION_TOKEN:-}" ]]     && DOCKER_RUN+=(-e "AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}")
    [[ -n "${AWS_REGION}" ]]              && DOCKER_RUN+=(-e "AWS_DEFAULT_REGION=${AWS_REGION}")
    if [[ -d "${HOME}/.aws" ]]; then
      DOCKER_RUN+=(-v "${HOME}/.aws:/root/.aws:ro")
      [[ -n "${AWS_PROFILE}" ]] && DOCKER_RUN+=(-e "AWS_PROFILE=${AWS_PROFILE}")
    fi
  fi

  # GCP credentials
  if [[ "${PROVIDER}" == "gcp" ]] && [[ "${MODE}" != "external" ]]; then
    DOCKER_RUN+=(-e "GOOGLE_CLOUD_PROJECT=${GCP_PROJECT}")
    if [[ -d "${HOME}/.config/gcloud" ]]; then
      DOCKER_RUN+=(-v "${HOME}/.config/gcloud:/root/.config/gcloud:ro")
    fi
  fi

  # Output mount
  DOCKER_RUN+=(-v "${ABS_OUTPUT}:/app/output")
  DOCKER_RUN+=(stratus-ai "${CLI_ARGS[@]}")

  echo -e "\n  ${DIM}Running: docker run ... stratus-ai ${CLI_ARGS[*]}${NC}\n"
  "${DOCKER_RUN[@]}"

else
  # Local Python run
  CLI_ARGS[7]="--output-dir"
  CLI_ARGS[8]="${ABS_OUTPUT}"

  [[ -n "${AWS_PROFILE}" ]] && CLI_ARGS+=(--profile "${AWS_PROFILE}")

  # Update local output-dir arg (index may vary — just rebuild)
  LOCAL_ARGS=("${CLI_ARGS[@]}")
  # Replace /app/output with ABS_OUTPUT
  LOCAL_ARGS=("${LOCAL_ARGS[@]/\/app\/output/${ABS_OUTPUT}}")

  echo -e "\n  ${DIM}Running: python -m assessment.cli ${LOCAL_ARGS[*]}${NC}\n"
  cd "${SCRIPT_DIR}"
  python3 -m assessment.cli "${LOCAL_ARGS[@]}"
fi

# =============================================================================
# Done
# =============================================================================
echo ""
echo -e "${BOLD}${GREEN}"
cat <<'DONE'
  ╔══════════════════════════════════════════╗
  ║   Assessment complete!                   ║
  ╚══════════════════════════════════════════╝
DONE
echo -e "${NC}"
ok "Reports saved to: ${ABS_OUTPUT}/"
echo ""

# Try to open HTML report
HTML_REPORT=$(find "${ABS_OUTPUT}" -name "*.html" 2>/dev/null | sort | tail -1)
if [[ -n "${HTML_REPORT}" ]]; then
  ok "HTML report: ${HTML_REPORT}"
  if command -v xdg-open &>/dev/null; then
    xdg-open "${HTML_REPORT}" 2>/dev/null &
  elif command -v open &>/dev/null; then
    open "${HTML_REPORT}" 2>/dev/null &
  fi
fi

echo -e "\n  ${DIM}To re-run with the same settings:${NC}"
echo -e "  bash wizard.sh\n"
