#!/usr/bin/env bash
# =============================================================================
# StratusAI Wizard — run a scan OR deploy infrastructure
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

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

# ask_choice <varname> <prompt> <opt1> <opt2> ...  — default is always 1
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
    if [[ "$chosen" =~ ^[0-9]+$ ]] && (( chosen >= 1 && chosen <= total )); then break; fi
    err "Please enter a number between 1 and ${total}."
  done
  printf -v "$varname" '%s' "$chosen"
}

# confirm <prompt> — returns 0 for yes
confirm() {
  echo -en "  ${BOLD}$1${NC} ${DIM}[y/N]${NC}: "
  read -r ans
  [[ "${ans:-}" =~ ^[Yy]$ ]]
}

# pick_gcp_project <varname> <prompt>
# Shows numbered list of accessible GCP projects; falls back to manual entry.
pick_gcp_project() {
  local varname="$1" prompt="$2"
  local detected; detected=$(gcloud config get-value project 2>/dev/null || echo "")
  info "Fetching accessible GCP projects..."
  local pids=() plabels=()
  while IFS=$'\t' read -r pid pname; do
    [[ -z "$pid" ]] && continue
    pids+=("$pid"); plabels+=("${pid}  —  ${pname}")
  done < <(gcloud projects list --format="value(projectId,name)" 2>/dev/null | sort)

  if [[ "${#pids[@]}" -gt 0 ]]; then
    plabels+=("Enter project ID manually")
    local n
    ask_choice n "$prompt" "${plabels[@]}"
    if (( n <= ${#pids[@]} )); then
      printf -v "$varname" '%s' "${pids[$((n - 1))]}"
      ok "Selected: ${pids[$((n - 1))]}"
    else
      local manual=""
      ask manual "GCP project ID" "$detected"
      while [[ -z "$manual" ]]; do err "Project ID is required."; ask manual "GCP project ID" ""; done
      printf -v "$varname" '%s' "$manual"
    fi
  else
    warn "Could not list projects — enter project ID manually."
    local manual=""
    ask manual "GCP project ID" "$detected"
    while [[ -z "$manual" ]]; do err "Project ID is required."; ask manual "GCP project ID" ""; done
    printf -v "$varname" '%s' "$manual"
  fi
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
  ╚══════════════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"

# =============================================================================
# Step 0 — What do you want to do?
# =============================================================================
section "Step 0 — What would you like to do?"

ask_choice WIZARD_MODE_N "Choose an action:" \
  "Run a scan now        — assess AWS / GCP / external target (local or Docker)" \
  "Deploy infrastructure — set up Cloud Run Job (GCP) or ECS Fargate (AWS) + scheduler"

# ─────────────────────────────────────────────────────────────────────────────
# ███████╗ ██████╗ █████╗ ███╗   ██╗    ██████╗  █████╗ ████████╗██╗  ██╗
# ██╔════╝██╔════╝██╔══██╗████╗  ██║    ██╔══██╗██╔══██╗╚══██╔══╝██║  ██║
# ███████╗██║     ███████║██╔██╗ ██║    ██████╔╝███████║   ██║   ███████║
# ╚════██║██║     ██╔══██║██║╚██╗██║    ██╔═══╝ ██╔══██║   ██║   ██╔══██║
# ███████║╚██████╗██║  ██║██║ ╚████║    ██║     ██║  ██║   ██║   ██║  ██║
# ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
# =============================================================================
if [[ "$WIZARD_MODE_N" == "1" ]]; then

echo -e "  ${DIM}Run a scan interactively. Takes about 2 minutes to configure.${NC}\n"

# ── Scan Step 1: Execution mode ───────────────────────────────────────────────
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

# ── Scan Step 2: Cloud Provider ───────────────────────────────────────────────
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

# ── Scan Step 3: Scan Mode & Target ───────────────────────────────────────────
section "Step 3 of 7 — Scan Mode"

MODE="" TARGET=""

if [[ "$PROVIDER" == "external" ]]; then
  PROVIDER="aws"
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

# ── Scan Step 4: Cloud Credentials ────────────────────────────────────────────
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
    pick_gcp_project GCP_PROJECT "Select GCP project to scan:"
    ask GCP_REGION "GCP region" "us-central1"
    ok "Project: ${GCP_PROJECT} (${GCP_REGION})"
  fi
fi

# ── Scan Step 5: AI Model & API Key ───────────────────────────────────────────
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

# ── Scan Step 6: Scan Options ─────────────────────────────────────────────────
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

# ── Scan Step 7: Review & Run ─────────────────────────────────────────────────
section "Step 7 of 7 — Review"

echo -e "  ${BOLD}Configuration summary:${NC}\n"
printf "  %-16s %s\n" "Provider:"  "${PROVIDER^^}"
printf "  %-16s %s\n" "Mode:"      "$MODE"
[[ -n "$TARGET" ]]         && printf "  %-16s %s\n" "Target:"      "$TARGET"
[[ -n "$GCP_PROJECT" ]]    && printf "  %-16s %s\n" "GCP Project:" "${GCP_PROJECT} (${GCP_REGION})"
[[ -n "$AWS_REGION" ]]     && printf "  %-16s %s\n" "Region:"      "$AWS_REGION"
[[ -n "$AWS_PROFILE" ]]    && printf "  %-16s %s\n" "AWS Profile:" "$AWS_PROFILE"
printf "  %-16s %s\n" "AI Model:"  "$MODEL"
printf "  %-16s %s\n" "Severity:"  "${SEVERITY}+"
[[ -n "$MODULES_FILTER" ]] && printf "  %-16s %s\n" "Modules:"     "$MODULES_FILTER"
printf "  %-16s %s\n" "Context:"   "$CONTEXT"
printf "  %-16s %s\n" "Output:"    "$OUTPUT_DIR"
printf "  %-16s %s\n" "Docker:"    "$USE_DOCKER"
echo; hr

confirm "Launch StratusAI with these settings?" || {
  echo -e "\n  Cancelled. Re-run ${BOLD}bash wizard.sh${NC} to start over.\n"
  exit 0
}

# ── Build & run the command ───────────────────────────────────────────────────
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
[[ -n "$TARGET" ]]         && CLI_ARGS+=(--target  "$TARGET")
[[ -n "$MODULES_FILTER" ]] && CLI_ARGS+=(--modules "$MODULES_FILTER")
[[ -n "$GCP_PROJECT" ]]    && CLI_ARGS+=(--project "$GCP_PROJECT")
[[ -n "$AWS_REGION" ]]     && CLI_ARGS+=(--region  "$AWS_REGION")

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
    [[ -d "${HOME}/.aws" ]]               && DOCKER_RUN+=(-v "${HOME}/.aws:/root/.aws:ro")
    [[ -n "$AWS_PROFILE" ]]               && DOCKER_RUN+=(-e "AWS_PROFILE=${AWS_PROFILE}")
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

# ── Done ─────────────────────────────────────────────────────────────────────
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

shopt -s nullglob
REPORT_FILES=("${ABS_OUTPUT}"/*.html "${ABS_OUTPUT}"/*.md "${ABS_OUTPUT}"/*.json)
shopt -u nullglob

if [[ "${#REPORT_FILES[@]}" -gt 0 ]]; then
  echo -e "  ${BOLD}Generated reports:${NC}"
  for f in "${REPORT_FILES[@]}"; do
    case "$f" in
      *.html) icon="🌐" ;; *.md) icon="📄" ;; *.json) icon="📋" ;; *) icon="📁" ;;
    esac
    echo -e "    ${icon}  ${CYAN}file://${f}${NC}"
  done
  echo ""
fi

HTML_REPORT=$(find "${ABS_OUTPUT}" -name "*.html" 2>/dev/null | sort | tail -1 || true)
if [[ -n "${HTML_REPORT:-}" ]]; then
  echo -e "  ${BOLD}Open in browser:${NC}"
  echo -e "    ${GREEN}file://${HTML_REPORT}${NC}"
  echo ""
  command -v xdg-open &>/dev/null && xdg-open "$HTML_REPORT" &>/dev/null & true
  command -v open      &>/dev/null && open      "$HTML_REPORT" &>/dev/null & true
fi

# ── Cleanup ───────────────────────────────────────────────────────────────────
echo; hr
echo -e "  ${BOLD}Cleanup options${NC}\n"

if $USE_DOCKER && confirm "Remove the local Docker image (stratus-ai)?"; then
  docker rmi stratus-ai 2>/dev/null && ok "Docker image removed." || warn "Image not found."
fi
if [[ -d "$ABS_OUTPUT" ]] && confirm "Delete report files in ${ABS_OUTPUT}?"; then
  rm -rf "${ABS_OUTPUT:?}"/* && ok "Output directory cleared."
fi

echo -e "\n  ${DIM}To re-run: bash wizard.sh${NC}\n"

# ─────────────────────────────────────────────────────────────────────────────
# ██████╗ ███████╗██████╗ ██╗      ██████╗ ██╗   ██╗
# ██╔══██╗██╔════╝██╔══██╗██║     ██╔═══██╗╚██╗ ██╔╝
# ██║  ██║█████╗  ██████╔╝██║     ██║   ██║ ╚████╔╝
# ██║  ██║██╔══╝  ██╔═══╝ ██║     ██║   ██║  ╚██╔╝
# ██████╔╝███████╗██║     ███████╗╚██████╔╝   ██║
# ╚═════╝ ╚══════╝╚═╝     ╚══════╝ ╚═════╝    ╚═╝
# =============================================================================
elif [[ "$WIZARD_MODE_N" == "2" ]]; then

echo -e "  ${DIM}Deploy StratusAI to AWS (ECS Fargate) or GCP (Cloud Run Job).${NC}\n"

# ── Deploy Step 1: Platform ───────────────────────────────────────────────────
section "Step 1 — Target cloud platform"

ask_choice PLATFORM_N "Where do you want to deploy StratusAI?" \
  "AWS  — ECS Fargate + ECR + S3 + SSM + EventBridge" \
  "GCP  — Cloud Run Job + Artifact Registry + GCS + Secret Manager + Cloud Scheduler"

[[ "$PLATFORM_N" == "1" ]] && PLATFORM="aws" || PLATFORM="gcp"
ok "Deploying to: ${PLATFORM^^}"

# ── Deploy Step 2: Check dependencies ────────────────────────────────────────
section "Step 2 — Checking dependencies"

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

# =============================================================================
# AWS DEPLOYMENT PATH
# =============================================================================
if [[ "$PLATFORM" == "aws" ]]; then

section "Step 3 — AWS authentication"

echo -e "  Available profiles:"
aws configure list-profiles 2>/dev/null | while read -r p; do echo "    • $p"; done || \
  info "(no profiles found — using environment credentials)"
echo

ask AWS_PROFILE "AWS profile" "default"
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

# ──────────────────────────────────────────────────────────────────────────────
section "Step 4 — Deployment settings"

ask AWS_REGION   "AWS region" "us-east-1"
ask NAME_PREFIX  "Resource name prefix" "stratusai"
ask ENVIRONMENT  "Environment label (prod / staging)" "prod"

# ──────────────────────────────────────────────────────────────────────────────
section "Step 5 — Networking (VPC & subnets)"

echo -e "  ECS Fargate tasks need a VPC and at least one public subnet."
echo
ask_choice NET_N "VPC:" \
  "Auto — use existing default VPC (recommended)" \
  "Custom — specify VPC and subnet IDs"

VPC_ID=""; SUBNET_IDS=""
if [[ "$NET_N" == "2" ]]; then
  echo
  info "Fetching VPCs in ${AWS_REGION}..."
  aws ec2 describe-vpcs $PROFILE_ARG --region "$AWS_REGION" \
    --query 'Vpcs[*].[VpcId,CidrBlock,Tags[?Key==`Name`].Value|[0]]' \
    --output text 2>/dev/null | \
    while IFS=$'\t' read -r id cidr name; do
      printf "    %-22s  %-18s  %s\n" "$id" "$cidr" "${name:-<no name>}"
    done || warn "Could not list VPCs."
  echo
  ask VPC_ID "VPC ID (e.g. vpc-0abc1234)"
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
  ask SUBNET_IDS "Subnet IDs (comma-separated, e.g. subnet-aaa,subnet-bbb)"
fi

# ──────────────────────────────────────────────────────────────────────────────
section "Step 6 — AI model & API key"

echo -e "    1) claude-sonnet-4-6          ${CYAN}Anthropic  ~\$0.08/scan  (recommended)${NC}"
echo -e "    2) claude-haiku-4-5-20251001  ${CYAN}Anthropic  ~\$0.01/scan  (budget)${NC}"
echo -e "    3) claude-opus-4-6            ${CYAN}Anthropic  ~\$0.30/scan  (best quality)${NC}"
echo -e "    4) gpt-4o                     ${CYAN}OpenAI     ~\$0.10/scan${NC}"
echo -e "    5) gemini-2.0-flash           ${CYAN}Google     ~\$0.005/scan (cheapest)${NC}"
echo -e "    6) No AI                      ${CYAN}Free — raw scanner output only${NC}"
echo
ask_choice AI_N "Model:" \
  "claude-sonnet-4-6" "claude-haiku-4-5-20251001" "claude-opus-4-6" \
  "gpt-4o" "gemini-2.0-flash" "No AI"

ENABLE_AI="true"; AI_MODEL="claude-sonnet-4-6"; API_KEY=""
case "$AI_N" in
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
    *)        ENV_KEY=""; KEY_PREFIX="" ;;
  esac
  if [[ -n "${ENV_KEY:-}" ]]; then
    ok "API key found in environment (${ENV_KEY:0:10}...)"
    API_KEY="$ENV_KEY"
  else
    ask_secret API_KEY "API key"
  fi
  [[ -n "$KEY_PREFIX" && "$API_KEY" != ${KEY_PREFIX}* ]] && \
    warn "Key prefix doesn't match expected '${KEY_PREFIX}...' — double-check before deploying."
fi

# ──────────────────────────────────────────────────────────────────────────────
section "Step 7 — Scan configuration"

ask SCAN_REGIONS "AWS regions to scan (comma-separated)" "$AWS_REGION"
echo
echo -e "  Minimum severity filter:"
ask_choice SEV_N "Severity:" \
  "INFO (everything)" "LOW" "MEDIUM (recommended)" "HIGH" "CRITICAL (only showstoppers)"
case "$SEV_N" in
  1) SEVERITY="INFO" ;; 2) SEVERITY="LOW" ;; 3) SEVERITY="MEDIUM" ;;
  4) SEVERITY="HIGH" ;; 5) SEVERITY="CRITICAL" ;; *) SEVERITY="INFO" ;;
esac

echo
ENABLE_EXTERNAL="false"; EXTERNAL_TARGET=""
if confirm "Enable external scan (ports, SSL, headers, DNS)?"; then
  ENABLE_EXTERNAL="true"
  ask EXTERNAL_TARGET "Hostname or IP to scan (e.g. api.example.com)"
fi

echo
ask SCAN_MODULES    "Modules to run (comma-separated, Enter = all)" ""
echo
ask ACCOUNT_CONTEXT "Environment context for AI (e.g. 'Production fintech, PCI DSS')" ""

# ──────────────────────────────────────────────────────────────────────────────
section "Step 8 — Scheduled scans (optional)"

ENABLE_SCHEDULER="false"; SCHEDULE_EXPR="rate(7 days)"; NOTIFICATION_EMAIL=""
if confirm "Enable automatic scheduled scans via EventBridge?"; then
  ENABLE_SCHEDULER="true"
  echo
  echo -e "  Examples:  rate(7 days)   rate(1 day)   cron(0 8 * * ? *)"
  ask SCHEDULE_EXPR     "Schedule expression" "rate(7 days)"
  ask NOTIFICATION_EMAIL "Alert email on scan completion (leave blank to skip)" ""
fi

# ──────────────────────────────────────────────────────────────────────────────
section "Step 9 — Post-deploy"

RUN_AFTER_DEPLOY=false
confirm "Trigger a scan immediately after deployment?" && RUN_AFTER_DEPLOY=true

# ── AWS Summary ───────────────────────────────────────────────────────────────
echo; hr
echo -e "  ${BOLD}AWS Deployment Summary${NC}"; hr; echo
printf "  %-28s %s\n" "Account:"            "$ACCOUNT_ID"
printf "  %-28s %s\n" "Region:"             "$AWS_REGION"
printf "  %-28s %s\n" "Name prefix:"        "$NAME_PREFIX"
printf "  %-28s %s\n" "Environment:"        "$ENVIRONMENT"
echo
[[ -n "$VPC_ID" ]] \
  && printf "  %-28s %s\n" "VPC:" "$VPC_ID" \
  && printf "  %-28s %s\n" "Subnets:" "$SUBNET_IDS" \
  || printf "  %-28s %s\n" "VPC:" "Default (auto-discovered)"
echo
printf "  %-28s %s\n" "AI enabled:"         "$ENABLE_AI"
[[ "$ENABLE_AI" == "true" ]] && printf "  %-28s %s\n" "AI model:"   "$AI_MODEL"
[[ -n "$API_KEY" ]]          && printf "  %-28s %s\n" "API key:"    "${API_KEY:0:10}..."
echo
printf "  %-28s %s\n" "Scan regions:"       "$SCAN_REGIONS"
printf "  %-28s %s\n" "Severity filter:"    "$SEVERITY"
printf "  %-28s %s\n" "External scan:"      "$ENABLE_EXTERNAL"
[[ -n "$EXTERNAL_TARGET" ]]  && printf "  %-28s %s\n" "External target:" "$EXTERNAL_TARGET"
[[ -n "$SCAN_MODULES" ]]     && printf "  %-28s %s\n" "Modules:"    "$SCAN_MODULES"
[[ -n "$ACCOUNT_CONTEXT" ]]  && printf "  %-28s %s\n" "AI context:" "$ACCOUNT_CONTEXT"
echo
printf "  %-28s %s\n" "Scheduled scans:"    "$ENABLE_SCHEDULER"
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
# Generated by wizard.sh — $(date -u +"%Y-%m-%dT%H:%M:%SZ")

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
echo -e "    Logs:          ${CYAN}aws logs tail /aws/ecs/${NAME_PREFIX} --follow --region ${AWS_REGION}${NC}"
echo -e "    Re-deploy:     ${CYAN}./deploy.sh --build-only --region ${AWS_REGION}${NC}"
echo -e "    Trigger scan:  ${CYAN}./deploy.sh --run-only  --region ${AWS_REGION}${NC}"
echo -e "    Destroy:       ${CYAN}./deploy.sh --destroy   --region ${AWS_REGION}${NC}"
echo

# ── AWS Cleanup ───────────────────────────────────────────────────────────────
hr
echo -e "\n  ${BOLD}Cleanup${NC}\n"
if confirm "Destroy all AWS infrastructure now? (ECS, ECR, S3, SSM — cannot be undone)"; then
  echo
  warn "Destroying all StratusAI AWS infrastructure..."
  bash ./deploy.sh --destroy --region "$AWS_REGION"
  ok "Infrastructure destroyed."
else
  info "Infrastructure left running. Destroy later with: ./deploy.sh --destroy --region ${AWS_REGION}"
fi
echo

# =============================================================================
# GCP DEPLOYMENT PATH
# =============================================================================
elif [[ "$PLATFORM" == "gcp" ]]; then

section "Step 3 — GCP authentication"

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

# ──────────────────────────────────────────────────────────────────────────────
section "Step 4 — Project & region"

pick_gcp_project GCP_PROJECT "GCP project to deploy INTO:"
ask GCP_REGION   "GCP region" "us-central1"
ask NAME_PREFIX  "Resource name prefix" "stratusai"
ask ENVIRONMENT  "Environment label (prod / staging)" "prod"

info "Verifying project access..."
if gcloud projects describe "$GCP_PROJECT" &>/dev/null; then
  ok "Project ${GCP_PROJECT} is accessible."
else
  err "Cannot access project '${GCP_PROJECT}'. Check the ID and your permissions."
  exit 1
fi

# ──────────────────────────────────────────────────────────────────────────────
section "Step 5 — What to scan"

echo -e "  StratusAI can scan the same project it's deployed into, or a different one."
echo
ask_choice SCAN_PROJ_N "Scan target:" \
  "Same project (${GCP_PROJECT})" \
  "Different project"

SCAN_PROJECT=""
if [[ "$SCAN_PROJ_N" == "2" ]]; then
  echo
  pick_gcp_project SCAN_PROJECT "Project to scan:"
fi

# ──────────────────────────────────────────────────────────────────────────────
section "Step 6 — AI model & API key"

echo -e "    1) claude-sonnet-4-6          ${CYAN}Anthropic  ~\$0.08/scan  (recommended)${NC}"
echo -e "    2) claude-haiku-4-5-20251001  ${CYAN}Anthropic  ~\$0.01/scan  (budget)${NC}"
echo -e "    3) claude-opus-4-6            ${CYAN}Anthropic  ~\$0.30/scan  (best quality)${NC}"
echo -e "    4) gpt-4o                     ${CYAN}OpenAI     ~\$0.10/scan${NC}"
echo -e "    5) gemini-2.0-flash           ${CYAN}Google     ~\$0.005/scan (cheapest)${NC}"
echo -e "    6) No AI                      ${CYAN}Free — raw scanner output only${NC}"
echo
ask_choice AI_N "Model:" \
  "claude-sonnet-4-6" "claude-haiku-4-5-20251001" "claude-opus-4-6" \
  "gpt-4o" "gemini-2.0-flash" "No AI"

ENABLE_AI="true"; AI_MODEL="claude-sonnet-4-6"; API_KEY=""
case "$AI_N" in
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
    *)        ENV_KEY=""; KEY_PREFIX="" ;;
  esac
  if [[ -n "${ENV_KEY:-}" ]]; then
    ok "API key found in environment (${ENV_KEY:0:10}...)"
    API_KEY="$ENV_KEY"
  else
    ask_secret API_KEY "API key"
  fi
  [[ -n "$KEY_PREFIX" && "$API_KEY" != ${KEY_PREFIX}* ]] && \
    warn "Key prefix doesn't match '${KEY_PREFIX}...' — double-check."
fi

# ──────────────────────────────────────────────────────────────────────────────
section "Step 7 — Scan configuration"

echo -e "  Minimum severity filter:"
ask_choice SEV_N "Severity:" \
  "INFO (everything)" "LOW" "MEDIUM (recommended)" "HIGH" "CRITICAL (only showstoppers)"
case "$SEV_N" in
  1) SEVERITY="INFO" ;; 2) SEVERITY="LOW" ;; 3) SEVERITY="MEDIUM" ;;
  4) SEVERITY="HIGH" ;; 5) SEVERITY="CRITICAL" ;; *) SEVERITY="INFO" ;;
esac

echo
ENABLE_EXTERNAL="false"; EXTERNAL_TARGET=""
if confirm "Enable external scan (ports, SSL, headers, DNS)?"; then
  ENABLE_EXTERNAL="true"
  ask EXTERNAL_TARGET "Hostname or IP to scan (e.g. api.example.com)"
fi

echo
ask SCAN_MODULES    "Modules to run (comma-separated, Enter = all)" ""
echo
ask ACCOUNT_CONTEXT "Environment context for AI (e.g. 'Production SaaS, GDPR scope')" ""

# ──────────────────────────────────────────────────────────────────────────────
section "Step 8 — Scheduled scans (optional)"

ENABLE_SCHEDULER="false"; SCHEDULE_EXPR="0 8 * * 1"; NOTIFICATION_EMAIL=""
if confirm "Enable automatic scheduled scans via Cloud Scheduler?"; then
  ENABLE_SCHEDULER="true"
  echo
  echo -e "  Cron syntax (UTC). Examples:"
  echo -e "    0 8 * * 1    — every Monday at 08:00"
  echo -e "    0 8 * * *    — every day at 08:00"
  echo -e "    0 */6 * * *  — every 6 hours"
  ask SCHEDULE_EXPR      "Cron expression" "0 8 * * 1"
  ask NOTIFICATION_EMAIL "Alert email (leave blank to skip)" ""
fi

# ──────────────────────────────────────────────────────────────────────────────
section "Step 9 — Post-deploy"

RUN_AFTER_DEPLOY=false
confirm "Trigger a scan immediately after deployment?" && RUN_AFTER_DEPLOY=true

# ── GCP Summary ───────────────────────────────────────────────────────────────
echo; hr
echo -e "  ${BOLD}GCP Deployment Summary${NC}"; hr; echo
printf "  %-28s %s\n" "Deploy to project:"  "$GCP_PROJECT"
printf "  %-28s %s\n" "Scan project:"       "${SCAN_PROJECT:-${GCP_PROJECT} (same)}"
printf "  %-28s %s\n" "Region:"             "$GCP_REGION"
printf "  %-28s %s\n" "Name prefix:"        "$NAME_PREFIX"
printf "  %-28s %s\n" "Environment:"        "$ENVIRONMENT"
echo
printf "  %-28s %s\n" "AI enabled:"         "$ENABLE_AI"
[[ "$ENABLE_AI" == "true" ]] && printf "  %-28s %s\n" "AI model:"   "$AI_MODEL"
[[ -n "$API_KEY" ]]          && printf "  %-28s %s\n" "API key:"    "${API_KEY:0:10}..."
echo
printf "  %-28s %s\n" "Severity filter:"    "$SEVERITY"
printf "  %-28s %s\n" "External scan:"      "$ENABLE_EXTERNAL"
[[ -n "$EXTERNAL_TARGET" ]]  && printf "  %-28s %s\n" "External target:" "$EXTERNAL_TARGET"
[[ -n "$SCAN_MODULES" ]]     && printf "  %-28s %s\n" "Modules:"    "$SCAN_MODULES"
[[ -n "$ACCOUNT_CONTEXT" ]]  && printf "  %-28s %s\n" "AI context:" "$ACCOUNT_CONTEXT"
echo
printf "  %-28s %s\n" "Scheduled scans:"    "$ENABLE_SCHEDULER"
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
# Generated by wizard.sh — $(date -u +"%Y-%m-%dT%H:%M:%SZ")

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

# ── Phase 1: Enable APIs + Artifact Registry ──────────────────────────────────
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

# ── Phase 2: Everything else ──────────────────────────────────────────────────
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
echo -e "    Image:    ${CYAN}${IMAGE_PATH}${NC}"
[[ -n "$BUCKET" ]] && echo -e "    Reports:  ${CYAN}gs://${BUCKET}/reports/${NC}"
echo
echo -e "  Useful commands:"
echo -e "    Trigger scan:  ${CYAN}${RUN_CMD}${NC}"
echo -e "    View logs:     ${CYAN}gcloud logging read 'resource.type=cloud_run_job AND resource.labels.job_name=${JOB_NAME}' --project ${GCP_PROJECT} --limit 50${NC}"
echo -e "    Re-deploy:     ${CYAN}docker build -t ${IMAGE_PATH} . && docker push ${IMAGE_PATH}${NC}"
echo -e "    Destroy:       ${CYAN}terraform -chdir=./terraform/gcp destroy${NC}"
echo

# ── GCP Cleanup ───────────────────────────────────────────────────────────────
hr
echo -e "\n  ${BOLD}Cleanup${NC}\n"
if confirm "Destroy all GCP infrastructure now? (Cloud Run, Artifact Registry, GCS, Secret Manager — cannot be undone)"; then
  echo
  warn "Destroying all StratusAI GCP infrastructure..."
  BUCKET_NAME="${GCP_PROJECT}-${NAME_PREFIX}-reports"
  if gsutil ls "gs://${BUCKET_NAME}" &>/dev/null; then
    info "Emptying gs://${BUCKET_NAME} before destroy..."
    gsutil -m rm -r "gs://${BUCKET_NAME}/**" 2>/dev/null || true
  fi
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
fi  # end deploy path
