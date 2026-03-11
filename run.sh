#!/usr/bin/env bash
set -euo pipefail

IMAGE="stratusai:latest"
OUTPUT_DIR="$(pwd)/output"

# ── Validate API key ──────────────────────────────────────────────────────────
if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "ERROR: ANTHROPIC_API_KEY is not set."
  echo "  export ANTHROPIC_API_KEY=sk-ant-..."
  exit 1
fi

# ── Build image ───────────────────────────────────────────────────────────────
echo "► Building StratusAI image..."
docker build -q -t "$IMAGE" . || {
  echo "ERROR: Docker build failed."
  exit 1
}

# ── Show what access is needed ────────────────────────────────────────────────
MODE="${*}"
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║              StratusAI — Cloud Security Assessment            ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "This tool will:"
echo "  • Read your cloud account configuration via SDK (read-only API calls)"
echo "  • Perform external network/SSL/DNS scans if --target is specified"
echo "  • Send preprocessed findings to the Anthropic API for AI analysis"
echo "  • Write reports to ./output/ (created if not present)"
echo ""
echo "Data sent to Anthropic: cloud resource configuration (no secrets, no data)"
echo "This tool does NOT modify any cloud resources."
echo ""
read -r -p "Proceed? [y/N] " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
  echo "Aborted."
  exit 0
fi

# ── Run ───────────────────────────────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR"
echo ""

# Pass AWS credentials from environment if present
ENV_ARGS=(
  -e "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}"
)

[ -n "${AWS_ACCESS_KEY_ID:-}" ]     && ENV_ARGS+=(-e "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}")
[ -n "${AWS_SECRET_ACCESS_KEY:-}" ] && ENV_ARGS+=(-e "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}")
[ -n "${AWS_SESSION_TOKEN:-}" ]     && ENV_ARGS+=(-e "AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}")
[ -n "${AWS_DEFAULT_REGION:-}" ]    && ENV_ARGS+=(-e "AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}")

# Mount AWS credentials file if it exists (for profile-based auth)
AWS_CREDS_ARGS=()
if [ -d "$HOME/.aws" ]; then
  AWS_CREDS_ARGS=(-v "$HOME/.aws:/root/.aws:ro")
fi

# Mount GCP credentials if set
GCP_ARGS=()
if [ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ] && [ -f "${GOOGLE_APPLICATION_CREDENTIALS}" ]; then
  GCP_ARGS=(
    -v "${GOOGLE_APPLICATION_CREDENTIALS}:/tmp/gcp_creds.json:ro"
    -e "GOOGLE_APPLICATION_CREDENTIALS=/tmp/gcp_creds.json"
  )
fi

docker run --rm -it \
  "${ENV_ARGS[@]}" \
  "${AWS_CREDS_ARGS[@]}" \
  "${GCP_ARGS[@]}" \
  -v "$OUTPUT_DIR:/app/output" \
  --network host \
  "$IMAGE" \
  "$@"
