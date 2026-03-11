# StratusAI

**AI-powered cloud security assessment tool — runs entirely inside Docker.**

StratusAI scans your cloud environment for misconfigurations and vulnerabilities, feeds the findings to Claude, and produces a prioritized security report with attack chain analysis — from a single command.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
./run.sh --provider aws --mode internal
```

> Supports **AWS** (full), GCP/Azure (coming soon), and **external** endpoint scanning for any target.

---

## Two Assessment Modes

```
┌──────────────────────────────────────────────────────┐
│                    DOCKER CONTAINER                  │
│                                                      │
│  ┌─────────────────┐    ┌────────────────────────┐   │
│  │  INTERNAL MODE  │    │    EXTERNAL MODE       │   │
│  │                 │    │                        │   │
│  │  AWS/GCP/Azure  │    │  Any public target     │   │
│  │  SDK calls      │    │  nmap port scan        │   │
│  │  (read-only)    │    │  TLS/SSL analysis      │   │
│  │                 │    │  HTTP security headers │   │
│  │  IAM, S3, EC2   │    │  DNS/DNSSEC/SPF/DMARC  │   │
│  │  RDS, VPC,      │    │                        │   │
│  │  CloudTrail...  │    │                        │   │
│  └────────┬────────┘    └───────────┬────────────┘   │
│           └────────────┬────────────┘                │
│                        ▼                             │
│              AI Analysis (Claude)                    │
│              Attack Chains + Priorities              │
│                        ▼                             │
│              HTML + Markdown Reports                 │
└──────────────────────────────────────────────────────┘
```

**Internal mode** — uses cloud provider credentials (AWS keys, IAM role, GCP service account) to read your account's configuration via SDK. Finds IAM misconfigurations, public S3 buckets, insecure security groups, unencrypted databases, disabled logging, etc.

**External mode** — scans public endpoints from the outside. No cloud credentials needed. Finds open ports, TLS/certificate issues, missing HTTP security headers, DNS misconfigurations, email spoofing exposure.

**Both** — run everything at once (default).

---

## Requirements

- Docker (any recent version)
- Linux, macOS, or WSL2
- [Anthropic API key](https://console.anthropic.com/) — ~$0.05–0.20 per scan
- Cloud credentials (for internal mode):
  - **AWS**: access key + secret, or IAM role, or `~/.aws/credentials` profile
  - **GCP**: service account JSON (coming soon)
  - **Azure**: service principal (coming soon)

---

## Quick Start

**1. Install Docker:**
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER && newgrp docker
```

**2. Clone and run:**
```bash
git clone https://github.com/anpa1200/StratusAI.git
cd StratusAI

export ANTHROPIC_API_KEY=sk-ant-...

# AWS internal scan
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
./run.sh --provider aws --mode internal

# External endpoint scan (no cloud creds needed)
./run.sh --mode external --target company.com

# Full scan: AWS internal + external endpoint
./run.sh --provider aws --target company.com --mode both
```

Reports are written to `./output/`.

---

## Usage

```bash
# AWS full internal assessment (all 5 modules)
./run.sh --provider aws --mode internal

# AWS with named profile from ~/.aws/credentials
./run.sh --provider aws --mode internal --profile production

# Specific region
./run.sh --provider aws --mode internal --region eu-west-1

# Scan all default regions (us-east-1, us-west-2, eu-west-1)
./run.sh --provider aws --mode internal --all-regions

# External scan only (no cloud credentials needed)
./run.sh --mode external --target api.company.com

# Both internal + external
./run.sh --provider aws --mode both --target company.com

# Specific modules only
./run.sh --provider aws --mode internal --modules iam,s3

# Skip a module
./run.sh --provider aws --mode internal --skip rds

# No AI — raw scanner output as JSON (no API calls)
./run.sh --provider aws --mode internal --no-ai

# Show only HIGH and CRITICAL findings
./run.sh --provider aws --mode internal --severity HIGH

# Use Claude Opus for deeper analysis
./run.sh --provider aws --mode internal --model claude-opus-4-6

# Verbose output (preprocessor stats, AI timing)
./run.sh --provider aws --mode internal --verbose
```

### Docker Compose

```bash
ANTHROPIC_API_KEY=sk-ant-... \
AWS_ACCESS_KEY_ID=AKIA... \
AWS_SECRET_ACCESS_KEY=... \
docker compose run assessment --provider aws --mode internal
```

### Direct CLI (development — no Docker)

```bash
pip install -r requirements.txt
AWS_DEFAULT_REGION=us-east-1 python3 -m assessment.cli --provider aws --mode internal --no-ai
```

---

## AWS Scanner Modules

| Module | What it checks |
|--------|---------------|
| `iam` | Root account MFA, users without MFA, stale access keys (>90d), password policy, AdministratorAccess attachments, wildcard-trust roles |
| `s3` | Public buckets (ACL + bucket policy), account-level public access block, encryption at rest, versioning, access logging |
| `ec2` | Security groups open to 0.0.0.0/0 on sensitive ports, IMDSv2 enforcement, unencrypted EBS volumes, public snapshots, VPC flow logs |
| `cloudtrail` | CloudTrail enabled/multi-region/log validation, GuardDuty status, Security Hub findings, AWS Config recording, IAM Access Analyzer |
| `rds` | Publicly accessible instances, unencrypted storage, auto backups, deletion protection, IAM auth, insecure parameter groups |

## External Scanner Modules

| Module | What it checks |
|--------|---------------|
| `ports` | Open TCP ports (21 common ports via nmap), service identification |
| `ssl` | Certificate validity/expiry, TLS version (flags TLS 1.0/1.1), weak ciphers, HSTS |
| `http_headers` | Missing security headers (CSP, HSTS, X-Frame-Options, etc.), HTTP→HTTPS redirect, cookie security flags, version disclosure |
| `dns` | Zone transfer vulnerability, DNSSEC, SPF/DMARC/DKIM email security |

---

## The AI Analysis

**Pass 1 — Per-module:** Each module's output goes through a preprocessor that drops low-signal data (e.g. compliant IAM users, correctly configured buckets) before sending to Claude. This reduces prompt size 60–90%, cuts cost, and eliminates token limit errors.

**Pass 2 — Synthesis:** All module findings are combined in a single prompt asking Claude to identify:
- **Attack chains** — how multiple findings combine into real exploitation paths on *your specific account*
- **Top 10 priorities** — ranked by actual exploitability, not just severity label
- **Overall risk rating** — CRITICAL / HIGH / MEDIUM / LOW with justification
- **Executive summary** — non-technical prose for a CISO or account owner

---

## Required AWS Permissions

For a read-only assessment, attach this policy to your IAM user/role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:Get*", "iam:List*", "iam:GenerateCredentialReport",
        "s3:GetBucketAcl", "s3:GetBucketLogging", "s3:GetBucketPolicy",
        "s3:GetBucketVersioning", "s3:GetBucketEncryption",
        "s3:GetPublicAccessBlock", "s3:ListAllMyBuckets",
        "ec2:Describe*", "ec2:GetEbsEncryptionByDefault",
        "rds:Describe*",
        "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
        "guardduty:ListDetectors", "guardduty:GetDetector", "guardduty:ListFindings",
        "securityhub:GetFindings", "securityhub:DescribeHub",
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
        "access-analyzer:ListAnalyzers", "access-analyzer:ListFindings",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Project Structure

```
StratusAI/
├── Dockerfile
├── docker-compose.yml
├── run.sh                          # Host-side launcher with consent prompt
├── requirements.txt
└── assessment/
    ├── cli.py                      # Click CLI — entry point, orchestrates all stages
    ├── config.py                   # Thresholds, sensitive ports, IAM policy list
    ├── models.py                   # Finding, ModuleResult, AttackChain, Report dataclasses
    ├── runner.py                   # Stage 1 — parallel scanner execution
    ├── scanners/
    │   ├── base.py                 # Abstract BaseScanner with error isolation + timing
    │   ├── aws/
    │   │   ├── iam.py              # Root MFA, users, access keys, policies, roles
    │   │   ├── s3.py               # Public buckets, encryption, versioning, logging
    │   │   ├── ec2.py              # Security groups, instances, IMDSv2, EBS, VPCs
    │   │   ├── cloudtrail.py       # CloudTrail, GuardDuty, Security Hub, Config, Analyzer
    │   │   └── rds.py              # RDS instances, snapshots, parameter groups
    │   └── external/
    │       ├── port_scan.py        # nmap TCP port scan
    │       ├── ssl_scan.py         # TLS version, certificate validity, weak ciphers
    │       ├── http_headers.py     # HTTP security headers, cookie flags
    │       └── dns_scan.py         # Zone transfer, DNSSEC, SPF/DMARC/DKIM
    ├── ai/
    │   ├── client.py               # Anthropic SDK wrapper, retry + billing error handling
    │   ├── preprocessor.py         # Per-module data filter (60–90% size reduction)
    │   ├── prompts.py              # All prompt templates
    │   └── analyzer.py             # Stage 2 — sequential analysis + synthesis
    └── reports/
        ├── html.py                 # Self-contained dark-theme HTML (no CDN)
        └── markdown.py             # Markdown report generator
```

---

## Error Handling

| Error | Behavior |
|-------|----------|
| Scanner fails (permission denied, API error) | Records error in report, continues other modules |
| AWS credential missing/expired | Fails fast with actionable message |
| API rate limit (429) | Exponential backoff: 15s → 30s → 60s → 120s, up to 4 retries |
| Insufficient Anthropic credits (400) | Fails immediately with actionable message, suggests `--no-ai` |
| JSON decode error in AI response | Retries up to 4 times, records empty findings on final failure |

---

## Security Notes

- All AWS API calls are **read-only**. No resources are created, modified, or deleted.
- The only writable path is `./output/` on your host.
- Scan data is sent to the Anthropic API for AI analysis. Use `--no-ai` for air-gapped or regulated environments.
- Reports contain detailed cloud configuration — treat them like secrets. Don't commit to public repos.
- **Authorized use only** — run this on accounts you own or have explicit permission to assess.

---

## License

MIT
