#!/usr/bin/env bash
# =============================================================================
# StratusAI Wizard — Interactive setup and launch
# =============================================================================
set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────────────────────
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

# ask <varname> <prompt> [default]
ask() {
  local varname="$1" prompt="$2" default="${3:-}"
  local hint=""; [[ -n "$default" ]] && hint=" ${DIM}[${default}]${NC}"
  echo -en "  ${BOLD}${prompt}${NC}${hint}: "
  read -r value
  printf -v "$varname" '%s' "${value:-$default}"
}

# ask_secret <varname> <prompt>
ask_secret() {
  local varname="$1" prompt="$2"
  echo -en "  ${BOLD}${prompt}${NC}: "
  read -rs value; echo
  printf -v "$varname" '%s' "$value"
}

# ask_choice <varname> <prompt> <opt1> <opt2> ...
# Displays numbered menu, user types a number, stores the number in varname.
ask_choice() {
  local varname="$1" prompt="$2"; shift 2
  local opts=("$@") total="${#@}" i=1
  echo -e "  ${BOLD}${prompt}${NC}"
  for opt in "${opts[@]}"; do
    echo -e "    ${CYAN}${i})${NC}  ${opt}"
    ((i++))
  done
  local chosen
  while true; do
    echo -en "  Enter 1-${total} ${DIM}[1]${NC}: "
    read -r chosen
    chosen="${chosen:-1}"
    if [[ "$chosen" =~ ^[0-9]+$ ]] && (( chosen >= 1 && chosen <= total )); then
      break
    fi
    err "Please enter a number between 1 and ${total}."
  done
  printf -v "$varname" '%s' "$chosen"
}

# confirm <prompt> → returns 0 for yes
confirm() {
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
# Step 1: Execution mode
# =============================================================================
section "Step 1 of 7 — Execution Mode"

USE_DOCKER=false
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
  ok "Docker detected"
  if [[ -f "${SCRIPT_DIR}/Dockerfile" ]]; then
    ask_choice RUN_MODE_N "How would you like to run StratusAI?" \
      "Docker  (recommended — no local dependencies needed)" \
      "Local Python  (requires: pip install -r requirements.txt)"
    [[ "$RUN_MODE_N" == "1" ]] && USE_DOCKER=true
  else
    warn "Dockerfile not found — falling back to local Python"
  fi
else
  warn "Docker not available — using local Python"
fi

if $USE_DOCKER; then
  ok "Execution: Docker"
  info "Building Docker image (takes ~60s on first run)..."
  docker build -q -t stratus-ai "${SCRIPT_DIR}" && ok "Docker image ready"
else
  ok "Execution: Local Python"
  python3 -c "import assessment" &>/dev/null || \
    warn "assessment package not installed — run: pip install -r requirements.txt"
fi

# =============================================================================
# Step 2: Cloud Provider
# =============================================================================
section "Step 2 of 7 — Cloud Provider"

ask_choice PROVIDER_N "Which cloud environment do you want to assess?" \
  "AWS      — Amazon Web Services" \
  "GCP      — Google Cloud Platform" \
  "External — External-only scan (any public hostname, no cloud credentials)"

case "$PROVIDER_N" in
  1) PROVIDER="aws" ;;
  2) PROVIDER="gcp" ;;
  3) PROVIDER="external" ;;
esac
ok "Provider: ${PROVIDER}"

# =============================================================================
# Step 3: Scan Mode & Target
# =============================================================================
section "Step 3 of 7 — Scan Mode"

MODE="" TARGET=""

if [[ "$PROVIDER" == "external" ]]; then
  PROVIDER="aws"   # unused for external-only
  MODE="external"
  ask TARGET "Target hostname or IP (e.g. example.com)" ""
  while [[ -z "$TARGET" ]]; do
    err "Target is required for external mode."
    ask TARGET "Target hostname or IP" ""
  done
else
  ask_choice MODE_N "Scan mode:" \
    "Internal  — Cloud API scanning (IAM, storage, compute, …)" \
    "External  — Network scanning (ports, TLS, headers, DNS)" \
    "Both      — Internal + external (recommended)"
  case "$MODE_N" in
    1) MODE="internal" ;;
    2) MODE="external" ;;
    3) MODE="both" ;;
  esac

  if [[ "$MODE" != "internal" ]]; then
    ask TARGET "Target hostname or IP for external scan (Enter to skip)" ""
    if [[ -z "$TARGET" && "$MODE" == "both" ]]; then
      warn "No target provided — switching to internal-only."
      MODE="internal"
    fi
  fi
fi
ok "Mode: ${MODE}${TARGET:+ → ${TARGET}}"

# =============================================================================
# Step 4: Cloud Credentials
# =============================================================================
section "Step 4 of 7 — Cloud Credentials"

GCP_PROJECT="" AWS_PROFILE="" AWS_REGION="" GCP_REGION=""

if [[ "$MODE" != "external" ]]; then
  if [[ "$PROVIDER" == "aws" ]]; then
    echo -e "  AWS credentials are read from your environment or ~/.aws/credentials.\n"

    if aws sts get-caller-identity &>/dev/null 2>&1; then
      CURRENT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "unknown")
      CURRENT_ARN=$(aws sts get-caller-identity --query Arn    --output text 2>/dev/null || echo "unknown")
      ok "Active AWS credentials detected"
      info "Account:  ${CURRENT_ACCOUNT}"
      info "Identity: ${CURRENT_ARN}"
      ask AWS_PROFILE "AWS profile name (Enter for current default)" ""
    else
      warn "No active AWS credentials found."
      echo -e "    ${DIM}export AWS_ACCESS_KEY_ID=...${NC}"
      echo -e "    ${DIM}export AWS_SECRET_ACCESS_KEY=...${NC}"
      echo -e "    ${DIM}aws configure${NC}\n"
      confirm "Credentials configured? Continue?" || { echo "Exiting."; exit 1; }
      ask AWS_PROFILE "AWS profile name (Enter for default)" ""
    fi

    DEFAULT_REGION=$(aws configure get region 2>/dev/null || echo "us-east-1")
    ask AWS_REGION "AWS region" "$DEFAULT_REGION"

  elif [[ "$PROVIDER" == "gcp" ]]; then
    echo -e "  GCP uses Application Default Credentials (ADC).\n"

    if gcloud auth application-default print-access-token &>/dev/null 2>&1; then
      ok "GCP Application Default Credentials found"
    else
      warn "GCP ADC not configured."
      echo -e "  Run: ${DIM}gcloud auth application-default login${NC}\n"
      confirm "Credentials configured? Continue?" || { echo "Exiting."; exit 1; }
    fi

    DETECTED_PROJECT=$(gcloud config get-value project 2>/dev/null || echo "")

    info "Fetching accessible GCP projects..."
    GCP_PROJ_IDS=(); GCP_PROJ_LABELS=()
    while IFS=$'\t' read -r pid pname; do
      [[ -z "$pid" ]] && continue
      GCP_PROJ_IDS+=("$pid")
      GCP_PROJ_LABELS+=("${pid}  —  ${pname}")
    done < <(gcloud projects list --format="value(projectId,name)" 2>/dev/null | sort)

    if [[ "${#GCP_PROJ_IDS[@]}" -gt 0 ]]; then
      GCP_PROJ_LABELS+=("Enter project ID manually")
      ask_choice GCP_PROJ_N "Select GCP project to scan:" "${GCP_PROJ_LABELS[@]}"
      if (( GCP_PROJ_N <= ${#GCP_PROJ_IDS[@]} )); then
        GCP_PROJECT="${GCP_PROJ_IDS[$((GCP_PROJ_N - 1))]}"
        ok "Selected: ${GCP_PROJECT}"
      else
        ask GCP_PROJECT "GCP project ID" "$DETECTED_PROJECT"
        while [[ -z "$GCP_PROJECT" ]]; do
          err "GCP project ID is required."
          ask GCP_PROJECT "GCP project ID" ""
        done
      fi
    else
      warn "Could not list projects — enter project ID manually."
      ask GCP_PROJECT "GCP project ID" "$DETECTED_PROJECT"
      while [[ -z "$GCP_PROJECT" ]]; do
        err "GCP project ID is required."
        ask GCP_PROJECT "GCP project ID" ""
      done
    fi
    ask GCP_REGION "GCP region" "us-central1"
    ok "Project: ${GCP_PROJECT} (${GCP_REGION})"
  fi
fi

# =============================================================================
# Step 5: AI Model & API Key
# =============================================================================
section "Step 5 of 7 — AI Model"

echo -e "  ${DIM}Estimated cost per full scan:${NC}"
echo -e "    Gemini 2.0 Flash      ~\$0.01   fastest + cheapest"
echo -e "    Claude Haiku 4.5      ~\$0.01   fast + cheap"
echo -e "    GPT-4o mini           ~\$0.01   fast + cheap"
echo -e "    Claude Sonnet 4.6     ~\$0.06   best quality  ← default"
echo -e "    GPT-4o                ~\$0.06   good quality"
echo -e "    o3-mini               ~\$0.05   reasoning model"
echo -e "    Claude Opus 4.6       ~\$0.30   highest quality"
echo

ask_choice AI_PROVIDER_N "AI provider:" \
  "Anthropic  (Claude Sonnet / Haiku / Opus)" \
  "OpenAI     (GPT-4o, GPT-4o mini, o3-mini, o1)" \
  "Google     (Gemini 2.0 Flash, 1.5 Pro, 1.5 Flash)"

AI_KEY="" MODEL=""

case "$AI_PROVIDER_N" in
  1)
    ask_choice MODEL_N "Claude model:" \
      "claude-sonnet-4-6          Best quality  ~\$0.06/scan  (default)" \
      "claude-haiku-4-5-20251001  Fast & cheap  ~\$0.01/scan" \
      "claude-opus-4-6            Highest quality  ~\$0.30/scan"
    case "$MODEL_N" in
      1) MODEL="claude-sonnet-4-6" ;;
      2) MODEL="claude-haiku-4-5-20251001" ;;
      3) MODEL="claude-opus-4-6" ;;
    esac

    if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
      ok "ANTHROPIC_API_KEY already set in environment"
      AI_KEY="$ANTHROPIC_API_KEY"
    else
      ask_secret AI_KEY "Anthropic API key (sk-ant-...)"
      while [[ ! "$AI_KEY" =~ ^sk-ant- ]]; do
        err "Key must start with sk-ant-"
        ask_secret AI_KEY "Anthropic API key"
      done
    fi
    export ANTHROPIC_API_KEY="$AI_KEY"
    ;;

  2)
    ask_choice MODEL_N "OpenAI model:" \
      "gpt-4o       Best quality  ~\$0.06/scan" \
      "gpt-4o-mini  Fast & cheap  ~\$0.01/scan" \
      "o3-mini      Reasoning model  ~\$0.05/scan" \
      "o1           Advanced reasoning  ~\$0.25/scan"
    case "$MODEL_N" in
      1) MODEL="gpt-4o" ;;
      2) MODEL="gpt-4o-mini" ;;
      3) MODEL="o3-mini" ;;
      4) MODEL="o1" ;;
    esac

    if [[ -n "${OPENAI_API_KEY:-}" ]]; then
      ok "OPENAI_API_KEY already set in environment"
      AI_KEY="$OPENAI_API_KEY"
    else
      ask_secret AI_KEY "OpenAI API key (sk-...)"
      while [[ ! "$AI_KEY" =~ ^sk- ]]; do
        err "Key must start with sk-"
        ask_secret AI_KEY "OpenAI API key"
      done
    fi
    export OPENAI_API_KEY="$AI_KEY"
    ;;

  3)
    ask_choice MODEL_N "Gemini model:" \
      "gemini-2.0-flash  Fastest + cheapest  ~\$0.01/scan" \
      "gemini-1.5-pro    Higher quality  ~\$0.05/scan" \
      "gemini-1.5-flash  Balanced  ~\$0.02/scan"
    case "$MODEL_N" in
      1) MODEL="gemini-2.0-flash" ;;
      2) MODEL="gemini-1.5-pro" ;;
      3) MODEL="gemini-1.5-flash" ;;
    esac

    if [[ -n "${GOOGLE_API_KEY:-}" ]]; then
      ok "GOOGLE_API_KEY already set in environment"
    elif confirm "Use Application Default Credentials (ADC) instead of API key?"; then
      ok "Using ADC for Gemini"
    else
      ask_secret AI_KEY "Google API key (AIza...)"
      export GOOGLE_API_KEY="$AI_KEY"
    fi
    ;;
esac

ok "Model: ${MODEL}"

# =============================================================================
# Step 6: Scan Options
# =============================================================================
section "Step 6 of 7 — Scan Options"

ask_choice SEV_N "Minimum severity to include in the report:" \
  "INFO      Show all findings  (default)" \
  "LOW       Skip informational findings" \
  "MEDIUM    Show Medium and above  (recommended)" \
  "HIGH      Show High and Critical only" \
  "CRITICAL  Show Critical only"
case "$SEV_N" in
  1) SEVERITY="INFO" ;;  2) SEVERITY="LOW" ;;   3) SEVERITY="MEDIUM" ;;
  4) SEVERITY="HIGH" ;;  5) SEVERITY="CRITICAL" ;;
esac

MODULES_FILTER=""
if [[ "$MODE" != "external" ]]; then
  if ! confirm "Run all scanner modules?"; then
    if [[ "$PROVIDER" == "aws" ]]; then
      echo -e "\n  ${DIM}AWS modules: iam, s3, ec2, cloudtrail, rds, lambda, kms, secretsmanager, eks${NC}"
    else
      echo -e "\n  ${DIM}GCP modules: iam, compute, storage, cloudfunctions, cloudrun, secretmanager, logging${NC}"
    fi
    ask MODULES_FILTER "Modules to run, comma-separated (e.g. iam,s3,ec2)" ""
  fi
fi

echo
info "The AI uses environment context to sharpen severity ratings."
info "Example: 'Production fintech, PCI DSS scope'  or  'Dev environment, no real data'"
ask CONTEXT "Environment context" "Production environment — assume sensitive data"

ask OUTPUT_DIR "Report output directory" "./output"

# =============================================================================
# Step 7: Review & Run
# =============================================================================
section "Step 7 of 7 — Review"

echo -e "  ${BOLD}Configuration summary:${NC}\n"
printf "  %-16s %s\n" "Provider:"  "${PROVIDER^^}"
printf "  %-16s %s\n" "Mode:"      "$MODE"
[[ -n "$TARGET" ]]        && printf "  %-16s %s\n" "Target:"       "$TARGET"
[[ -n "$GCP_PROJECT" ]]   && printf "  %-16s %s\n" "GCP Project:"  "${GCP_PROJECT} (${GCP_REGION})"
[[ -n "$AWS_REGION" ]]    && printf "  %-16s %s\n" "Region:"       "$AWS_REGION"
[[ -n "$AWS_PROFILE" ]]   && printf "  %-16s %s\n" "AWS Profile:"  "$AWS_PROFILE"
printf "  %-16s %s\n" "AI Model:"  "$MODEL"
printf "  %-16s %s\n" "Severity:"  "${SEVERITY}+"
[[ -n "$MODULES_FILTER" ]] && printf "  %-16s %s\n" "Modules:"     "$MODULES_FILTER"
printf "  %-16s %s\n" "Context:"   "$CONTEXT"
printf "  %-16s %s\n" "Output:"    "$OUTPUT_DIR"
printf "  %-16s %s\n" "Docker:"    "$USE_DOCKER"
echo
hr

confirm "Launch StratusAI with these settings?" || {
  echo -e "\n  Cancelled. Re-run ${BOLD}bash wizard.sh${NC} to start over.\n"
  exit 0
}

# =============================================================================
# Build & run the command
# =============================================================================
section "Launching StratusAI"

mkdir -p "$OUTPUT_DIR"
ABS_OUTPUT="$(cd "$OUTPUT_DIR" && pwd)"

CLI_ARGS=(
  --provider "$PROVIDER"
  --mode     "$MODE"
  --model    "$MODEL"
  --severity "$SEVERITY"
  --context  "$CONTEXT"
  --output-dir /app/output
)
[[ -n "$TARGET" ]]         && CLI_ARGS+=(--target   "$TARGET")
[[ -n "$MODULES_FILTER" ]] && CLI_ARGS+=(--modules  "$MODULES_FILTER")
[[ -n "$GCP_PROJECT" ]]    && CLI_ARGS+=(--project  "$GCP_PROJECT")
[[ -n "$AWS_REGION" ]]     && CLI_ARGS+=(--region   "$AWS_REGION")

if $USE_DOCKER; then
  DOCKER_RUN=(docker run --rm)

  [[ -n "${ANTHROPIC_API_KEY:-}" ]] && DOCKER_RUN+=(-e "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}")
  [[ -n "${OPENAI_API_KEY:-}" ]]    && DOCKER_RUN+=(-e "OPENAI_API_KEY=${OPENAI_API_KEY}")
  [[ -n "${GOOGLE_API_KEY:-}" ]]    && DOCKER_RUN+=(-e "GOOGLE_API_KEY=${GOOGLE_API_KEY}")

  if [[ "$PROVIDER" == "aws" && "$MODE" != "external" ]]; then
    [[ -n "${AWS_ACCESS_KEY_ID:-}" ]]     && DOCKER_RUN+=(-e "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}")
    [[ -n "${AWS_SECRET_ACCESS_KEY:-}" ]] && DOCKER_RUN+=(-e "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}")
    [[ -n "${AWS_SESSION_TOKEN:-}" ]]     && DOCKER_RUN+=(-e "AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}")
    [[ -n "$AWS_REGION" ]]                && DOCKER_RUN+=(-e "AWS_DEFAULT_REGION=${AWS_REGION}")
    [[ -d "${HOME}/.aws" ]] && DOCKER_RUN+=(-v "${HOME}/.aws:/root/.aws:ro")
    [[ -n "$AWS_PROFILE" ]] && DOCKER_RUN+=(-e "AWS_PROFILE=${AWS_PROFILE}")
  fi

  if [[ "$PROVIDER" == "gcp" && "$MODE" != "external" ]]; then
    DOCKER_RUN+=(-e "GOOGLE_CLOUD_PROJECT=${GCP_PROJECT}")
    [[ -d "${HOME}/.config/gcloud" ]] && DOCKER_RUN+=(-v "${HOME}/.config/gcloud:/root/.config/gcloud:ro")
  fi

  DOCKER_RUN+=(-v "${ABS_OUTPUT}:/app/output")
  DOCKER_RUN+=(stratus-ai "${CLI_ARGS[@]}")

  echo -e "\n  ${DIM}Running: docker run … stratus-ai ${CLI_ARGS[*]}${NC}\n"
  "${DOCKER_RUN[@]}"

else
  LOCAL_ARGS=("${CLI_ARGS[@]/\/app\/output/${ABS_OUTPUT}}")
  [[ -n "$AWS_PROFILE" ]] && LOCAL_ARGS+=(--profile "$AWS_PROFILE")

  echo -e "\n  ${DIM}Running: python -m assessment.cli ${LOCAL_ARGS[*]}${NC}\n"
  cd "$SCRIPT_DIR"
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

HTML_REPORT=$(find "${ABS_OUTPUT}" -name "*.html" 2>/dev/null | sort | tail -1 || true)
if [[ -n "${HTML_REPORT:-}" ]]; then
  ok "HTML report: ${HTML_REPORT}"
  command -v xdg-open &>/dev/null && xdg-open "$HTML_REPORT" &>/dev/null & true
  command -v open      &>/dev/null && open      "$HTML_REPORT" &>/dev/null & true
fi

# =============================================================================
# Cleanup
# =============================================================================
echo
hr
echo -e "  ${BOLD}Cleanup options${NC}\n"

if $USE_DOCKER && confirm "Remove the local Docker image (stratus-ai)?"; then
  docker rmi stratus-ai 2>/dev/null && ok "Docker image removed." || warn "Image not found."
fi

if [[ -d "$ABS_OUTPUT" ]] && confirm "Delete report files in ${ABS_OUTPUT}?"; then
  rm -rf "${ABS_OUTPUT:?}"/* && ok "Output directory cleared."
fi

echo -e "\n  ${DIM}To re-run: bash wizard.sh${NC}\n"
