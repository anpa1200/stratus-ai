# StratusAI

**AI-powered multi-cloud security scanner for AWS and GCP — scan, analyze, deploy from a single wizard.**

StratusAI scans your cloud environment for misconfigurations and vulnerabilities, feeds findings to an LLM of your choice (Claude, GPT-4o, or Gemini), and produces a prioritized security report with attack chain analysis — all from one interactive wizard.

```bash
./wizard.sh   # option 1: run a scan  |  option 2: deploy to AWS or GCP
```

> **Full engineering walkthrough:** [StratusAI: I Built an AI-Powered Cloud Security Scanner for AWS and GCP — Here's Everything](https://medium.com/@1200km/stratusai-i-built-an-ai-powered-cloud-security-scanner-for-aws-and-gcp-heres-everything-89c6702d3b84)

---

## What It Does

- **9 AWS scanner modules** — IAM, S3, EC2, CloudTrail, RDS, Lambda, KMS, Secrets Manager, EKS
- **7 GCP scanner modules** — IAM, Compute Engine, Cloud Storage, Cloud Functions, Cloud Run, Secret Manager, Cloud Logging
- **4 external scan modules** — port scan (nmap), SSL/TLS, HTTP security headers, DNS/DMARC/SPF/DKIM
- **Multi-LLM AI analysis** — Claude (Anthropic), GPT-4o/o1/o3 (OpenAI), Gemini 2.0/1.5 (Google)
- **Attack chain synthesis** — identifies how multiple findings chain into real exploitation paths
- **HTML + Markdown + JSON reports** — interactive HTML with live search and severity filtering
- **Serverless deployment** — AWS ECS Fargate or GCP Cloud Run Job with optional scheduled scans

```
                      ┌──────────────────────────────────────────┐
                      │              StratusAI                   │
                      │                                          │
AWS credentials ────► │  ┌──────────┐   ┌───────────────────┐   │
GCP credentials ────► │  │ Scanners │   │    AI Layer       │   │
(no creds)      ────► │  │ AWS  (9) │──►│ Preprocessor      │──►│──► HTML report
                      │  │ GCP  (7) │   │ Per-module LLM    │   │    Markdown
                      │  │ Ext. (4) │   │ Synthesis         │   │    GCS/S3 upload
                      │  └──────────┘   └───────────────────┘   │
                      │  LLM Router: claude-* / gpt-* / gemini-* │
                      └──────────────────────────────────────────┘
```

---

## Quick Start

### Interactive wizard (recommended)

```bash
git clone https://github.com/anpa1200/stratus-ai
cd stratus-ai
chmod +x wizard.sh
./wizard.sh
```

The wizard opens with a mode selector:

```
  Step 0 — What would you like to do?
    1)  Run a scan now        — assess AWS / GCP / external target (local or Docker)
    2)  Deploy infrastructure — set up Cloud Run Job (GCP) or ECS Fargate (AWS) + scheduler
```

**Scan path (7 steps):** execution mode → cloud provider → scan mode → credentials → AI model → options → review & launch → clickable report links

**Deploy path (9 steps):** platform → dependencies → auth → project/settings → scan target → AI model → scan config → scheduler → post-deploy → terraform apply

For GCP, the wizard lists all accessible projects by number — no need to type project IDs.

### CLI directly

```bash
export ANTHROPIC_API_KEY=sk-ant-...

# AWS
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
python -m assessment.cli --provider aws --mode both --target your-domain.com

# GCP
gcloud auth application-default login
python -m assessment.cli --provider gcp --project my-gcp-project

# External only (no cloud credentials needed)
python -m assessment.cli --provider aws --mode external --target api.company.com
```

---

## Installation

**Docker (recommended — no local dependencies):**
```bash
docker build -t stratus-ai .
# wizard.sh handles docker run automatically
```

**Local Python:**
```bash
pip install -r requirements.txt
# External scan also needs: apt-get install nmap
```

---

## Supported AI Models

| Model | Provider | ~Cost/scan |
|---|---|---|
| `claude-sonnet-4-6` | Anthropic | ~$0.06 |
| `claude-haiku-4-5-20251001` | Anthropic | ~$0.01 |
| `claude-opus-4-6` | Anthropic | ~$0.30 |
| `gpt-4o` | OpenAI | ~$0.06 |
| `gpt-4o-mini` | OpenAI | ~$0.01 |
| `gemini-2.0-flash` | Google | ~$0.01 |
| `gemini-1.5-pro` | Google | ~$0.05 |

Low-signal modules (DNS, SSL, KMS, Cloud Logging) are automatically routed to cheaper models — saving 30–50% with no loss of quality.

---

## AWS Scanner Modules

| Module | What it checks |
|---|---|
| `iam` | Root MFA, users without MFA, stale access keys (>90d), password policy, AdministratorAccess, wildcard-trust roles |
| `s3` | Public buckets (ACL + policy), account-level public access block, encryption, versioning, access logging |
| `ec2` | Security groups open to 0.0.0.0/0, IMDSv1/v2, unencrypted EBS, public snapshots, VPC flow logs |
| `cloudtrail` | Multi-region trails, log validation, GuardDuty, Security Hub, AWS Config, IAM Access Analyzer |
| `rds` | Public instances, unencrypted storage, backups, deletion protection, IAM auth |
| `lambda` | Deprecated runtimes, public function URLs, unencrypted env vars, no VPC placement |
| `kms` | CMK rotation, public key policies |
| `secretsmanager` | Rotation status, KMS usage, public resource policies |
| `eks` | API endpoint public access, audit logging, secrets encryption, deprecated K8s versions |

## GCP Scanner Modules

| Module | What it checks |
|---|---|
| `iam` | `roles/owner` / `roles/editor` bindings, `allUsers` members, stale service account keys (>90d) |
| `compute` | OS Login disabled, serial port enabled, default SA with editor scope, open firewall rules |
| `storage` | Public buckets (`allUsers`), uniform access, versioning, CMEK, access logging |
| `cloudfunctions` | Public ingress, unauthenticated invocation, deprecated runtimes |
| `cloudrun` | Public access, unauthenticated invocation, minimal permissions |
| `secretmanager` | Rotation policy, overly-broad IAM bindings, stale secret versions |
| `logging` | Data Access audit logs disabled, no export sink, missing Admin Activity log capture |

## External Scanner Modules

| Module | What it checks |
|---|---|
| `ports` | Open TCP ports via nmap, service identification |
| `ssl` | Certificate validity/expiry, TLS 1.0/1.1, weak ciphers, HSTS |
| `http_headers` | Missing CSP/HSTS/X-Frame-Options, HTTP→HTTPS redirect, cookie flags, version disclosure |
| `dns` | Zone transfer, DNSSEC, SPF/DMARC/DKIM email security |

---

## Deployment

### AWS — ECS Fargate

```bash
./wizard.sh   # option 2 → AWS
# or manually:
cd terraform && cp terraform.tfvars.example terraform.tfvars
vim terraform.tfvars
terraform init && terraform apply
./deploy.sh
```

Creates: ECR repository, S3 reports bucket, SSM Parameter for API key, IAM roles, ECS cluster, EventBridge Scheduler.

### GCP — Cloud Run Job

```bash
./wizard.sh   # option 2 → GCP
```

The wizard handles the two-phase deploy automatically (Artifact Registry must exist before the image can be pushed, which must exist before Cloud Run Job can be created).

Creates: Artifact Registry, GCS reports bucket, Secret Manager secret, Cloud Run Job, Cloud Scheduler.

---

## Project Structure

```
cloud_audit/
├── assessment/
│   ├── cli.py                    # Click CLI entrypoint
│   ├── scanners/
│   │   ├── aws/                  # 9 AWS scanner modules
│   │   ├── gcp/                  # 7 GCP scanner modules
│   │   └── external/             # 4 external scanner modules
│   ├── ai/
│   │   ├── client.py             # LLM router: Anthropic / OpenAI / Google
│   │   ├── analyzer.py           # Per-module analysis + synthesis
│   │   └── preprocessor.py       # Smart data reduction (80%+ token savings)
│   └── reports/
│       ├── html.py               # Self-contained interactive HTML
│       └── markdown.py           # Markdown for git/docs/JIRA
├── tests/                        # 125 tests, zero cloud calls (moto + mocks)
├── terraform/                    # AWS ECS Fargate deployment
│   └── gcp/                      # GCP Cloud Run Job deployment
├── Dockerfile                    # Ubuntu 24.04 + Python + gcloud CLI + nmap
├── deploy.sh                     # AWS build-push-deploy helper
└── wizard.sh                     # Unified wizard: scan OR deploy
```

---

## Testing

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -v
# 125 passed — zero real cloud API calls, runs in ~11 seconds
```

---

## Security Notes

- All cloud API calls are **read-only**. No resources are created, modified, or deleted.
- Scan data is sent to your chosen LLM API. Use `--no-ai` for air-gapped environments.
- Reports contain detailed cloud configuration — treat them like secrets.
- **Authorized use only** — run this on accounts you own or have explicit permission to assess.

---

## License

MIT
