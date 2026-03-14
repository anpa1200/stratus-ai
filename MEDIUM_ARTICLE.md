# StratusAI: I Built an AI-Powered Cloud Security Scanner for AWS and GCP — Here's Everything

*A complete engineering walkthrough of building, testing, and deploying an intelligent multi-cloud security assessment tool using Python, Claude AI, and Terraform*

---

## Table of Contents

1. [The Problem Every Cloud Team Faces](#the-problem-every-cloud-team-faces)
2. [What StratusAI Does](#what-stratusai-does)
3. [Architecture Overview](#architecture-overview)
4. [Project Structure](#project-structure)
5. [Core Data Models](#core-data-models)
6. [The AWS Scanner Layer](#the-aws-scanner-layer)
   - [IAM Scanner: The Most Important One](#iam-scanner-the-most-important-one)
   - [S3 Scanner: The Breach Surface](#s3-scanner-the-breach-surface)
   - [Lambda Scanner: The Hidden Attack Surface](#lambda-scanner-the-hidden-attack-surface)
   - [EKS Scanner: The Kubernetes Layer](#eks-scanner-the-kubernetes-layer)
7. [The GCP Scanner Layer](#the-gcp-scanner-layer)
   - [GCP IAM Scanner](#gcp-iam-scanner)
   - [GCP Compute Scanner](#gcp-compute-scanner)
   - [GCP Storage Scanner](#gcp-storage-scanner)
   - [GCP Secret Manager & Logging Scanners](#gcp-secret-manager--logging-scanners)
8. [The AI Layer: Where the Magic Happens](#the-ai-layer-where-the-magic-happens)
   - [Preprocessing: Don't Send Everything to Claude](#preprocessing-dont-send-everything-to-claude)
   - [The Two-Stage AI Pipeline](#the-two-stage-ai-pipeline)
   - [The System Prompt: Making Claude a Security Expert](#the-system-prompt-making-claude-a-security-expert)
9. [The Report Layer](#the-report-layer)
   - [HTML Report with Live Search](#html-report-with-live-search)
   - [Markdown Report](#markdown-report)
10. [Testing Strategy: 125 Tests, Zero Cloud Calls](#testing-strategy-125-tests-zero-cloud-calls)
    - [Using moto for AWS Mocking](#using-moto-for-aws-mocking)
    - [Testing Report Generators Without AWS](#testing-report-generators-without-aws)
    - [Test Coverage](#test-coverage)
11. [Deployment: AWS ECS on Fargate](#deployment-aws-ecs-on-fargate)
    - [Terraform Setup](#terraform-setup)
    - [Deploying a New Image](#deploying-a-new-image)
    - [Running On-Demand](#running-on-demand-from-aws-console-or-cli)
12. [Deployment: GCP Cloud Run Job](#deployment-gcp-cloud-run-job)
    - [Architecture](#gcp-architecture)
    - [Terraform Setup](#gcp-terraform-setup)
    - [Two-Phase Deploy with the Wizard](#two-phase-deploy-with-the-wizard)
    - [Running On-Demand](#running-gcp-scans-on-demand)
13. [Running Locally](#running-locally)
14. [Quick Start with the Wizard](#quick-start-with-the-wizard)
15. [Lessons Learned](#lessons-learned)
16. [Cost and Performance](#cost-and-performance)
17. [What's Next](#whats-next)
18. [Full Quick-Start Reference](#full-quick-start-reference)
19. [Conclusion](#conclusion)

---

## The Problem Every Cloud Team Faces

Your cloud environment has been running for two years. You have 47 IAM users, 30+ S3 buckets, GCP service accounts with overly broad roles, EC2 instances in multiple regions, Cloud Run services, Lambda functions, and a Kubernetes cluster. You *know* there are misconfigurations. You just don't know which ones are actively dangerous versus which are theoretical.

Traditional security tools give you 800 raw findings and a risk score. They tell you "S3 bucket `logs-2021-archive` has versioning disabled" or "GCP service account has project-level Owner role." Great. Is that a P0 incident or a Tuesday afternoon task?

What you actually need is something that:
1. **Scans everything** across your AWS and GCP environments
2. **Understands context** — an unencrypted S3 bucket holding Lambda code *plus* an EC2 instance with IMDSv1 enabled *plus* an overprivileged IAM role is an attack chain, not three separate findings; same logic applies to GCP service account misconfigurations
3. **Prioritizes ruthlessly** — which 5 things should you fix before you close your laptop tonight?
4. **Explains in plain English** what an attacker could actually do

That's what I built: **StratusAI**, an open-source multi-cloud security assessment tool that combines traditional cloud API scanning (AWS via boto3, GCP via google-cloud SDK) with Claude AI for intelligent analysis and synthesis. This article is a complete engineering guide — architecture, code, testing, and deployment on both clouds included.

---

## What StratusAI Does

In a single CLI command:

```bash
# Scan AWS account
stratus --provider aws --mode both --target your-domain.com

# Scan GCP project
stratus --provider gcp --mode internal --project my-gcp-project
```

StratusAI will:

1. **Run 9 internal AWS scanner modules**: IAM, S3, EC2, CloudTrail, RDS, Lambda, KMS, Secrets Manager, EKS
2. **Run 7 internal GCP scanner modules**: IAM, Compute Engine, Cloud Storage, Cloud Functions, Cloud Run, Secret Manager, Cloud Logging
3. **Run 4 external scan modules** (cloud-agnostic): port scan (nmap), SSL/TLS analysis, HTTP security headers, DNS/email security (DMARC, SPF, DKIM)
4. **Send each module's raw data to an LLM of your choice** — Claude (Anthropic), GPT-4o/o1/o3 (OpenAI), or Gemini (Google)
5. **Synthesize everything cross-module** to identify attack chains (e.g., "public GCS bucket + overprivileged service account + metadata server access = credential theft path")
6. **Generate HTML and Markdown reports** with severity filtering, live search, and executive summary
7. **Deploy to AWS ECS** (Fargate) or **GCP Cloud Run Job** and run on a schedule via EventBridge or Cloud Scheduler

The result: an interactive HTML report you can share with your CISO, showing exactly which resources are at risk, what an attacker could do, and the specific CLI commands to fix it.

---

## Architecture Overview

```
                          ┌──────────────────────────────────────────┐
                          │              StratusAI                   │
                          │                                          │
  AWS credentials ──────► │  ┌──────────┐   ┌───────────────────┐   │
  GCP credentials ──────► │  │ Scanners │   │    AI Layer       │   │
  (no creds needed) ────► │  │          │   │                   │   │
                          │  │ AWS  (9) │──►│ Preprocessor      │   │
                          │  │ GCP  (7) │   │ Per-module LLM    │──►│──► HTML report
                          │  │ Ext. (4) │   │ Cross-module      │   │    Markdown
                          │  └──────────┘   │ Synthesis         │   │    GCS/S3 upload
                          │                 └───────────────────┘   │
                          │  ┌─────────────────────────────────┐    │
                          │  │  LLM Router                     │    │
                          │  │  claude-*  → Anthropic API      │    │
                          │  │  gpt-*/o*  → OpenAI API         │    │
                          │  │  gemini-*  → Google AI API      │    │
                          │  └─────────────────────────────────┘    │
                          └──────────────────────────────────────────┘
                                           │
                    ┌──────────────────────┴───────────────────────┐
                    │                                              │
             AWS deployment                                GCP deployment
          ECS Fargate + ECR + S3                Cloud Run Job + Artifact Registry
          + SSM + EventBridge                   + GCS + Secret Manager
                    │                           + Cloud Scheduler
             ./deploy.sh                              │
                                               ./wizard.sh
```

Two-stage AI pipeline:
- **Stage 1** — Each module is analyzed independently. The LLM returns structured JSON: findings (with severity, evidence, remediation), risk score, and module summary. Low-signal modules (DNS, SSL, KMS, Cloud Logging) are automatically downgraded to a cheaper model in the same provider family to cut costs.
- **Stage 2** — A synthesis pass takes all module summaries and findings, identifies attack chains, produces a top-10 priority list, executive summary, and overall risk rating.

---

## Project Structure

```
cloud_audit/
├── assessment/
│   ├── cli.py                    # Click CLI entrypoint (--provider aws|gcp, --project, ...)
│   ├── config.py                 # Thresholds, sensitive ports, model pricing
│   ├── models.py                 # Dataclasses: Finding, ModuleResult, Report, AttackChain
│   ├── runner.py                 # Parallel scanner execution (ThreadPoolExecutor)
│   ├── ai/
│   │   ├── client.py             # LLM router: Anthropic / OpenAI / Google APIs
│   │   ├── analyzer.py           # Per-module analysis + synthesis orchestration
│   │   ├── preprocessor.py       # Smart data reduction before sending to AI
│   │   └── prompts.py            # System prompt, module prompt, synthesis prompt
│   ├── scanners/
│   │   ├── base.py               # BaseScanner ABC
│   │   ├── aws/
│   │   │   ├── iam.py            # Users, roles, MFA, access keys, password policy
│   │   │   ├── s3.py             # Buckets, ACLs, encryption, versioning, policies
│   │   │   ├── ec2.py            # Instances, SGs, EBS, IMDSv1/v2, public IPs
│   │   │   ├── cloudtrail.py     # Trails, log validation, S3 delivery
│   │   │   ├── rds.py            # Instances, encryption, public access, backups
│   │   │   ├── lambda_scan.py    # Functions, deprecated runtimes, public URLs, env encryption
│   │   │   ├── kms.py            # CMKs, rotation, public key policies
│   │   │   ├── secrets_manager.py # Rotation, KMS usage, public resource policies
│   │   │   └── eks.py            # Clusters, API endpoint, logging, K8s version
│   │   ├── gcp/
│   │   │   ├── iam.py            # Service accounts, bindings, admin roles, key age
│   │   │   ├── compute.py        # VMs, firewall rules, OS Login, serial port, metadata
│   │   │   ├── storage.py        # Buckets, public ACLs, uniform access, encryption, logging
│   │   │   ├── cloudfunctions.py # Functions, public ingress, unauthenticated access, runtime
│   │   │   ├── cloudrun.py       # Services, public access, unauthenticated invocation
│   │   │   ├── secretmanager.py  # Secret versions, rotation, IAM bindings
│   │   │   └── logging.py        # Log sinks, audit log config, data access logs
│   │   └── external/
│   │       ├── port_scan.py      # nmap wrapper with XML parsing
│   │       ├── ssl_scan.py       # SSL/TLS certificate and cipher analysis
│   │       ├── http_headers.py   # Security header analysis
│   │       └── dns_scan.py       # DMARC, SPF, DKIM, CAA records
│   └── reports/
│       ├── html.py               # Interactive HTML with search and filtering
│       └── markdown.py           # Clean Markdown for git/docs
├── tests/
│   ├── conftest.py
│   ├── test_aws_scanners.py      # moto-based AWS integration tests
│   ├── test_gcp_scanners.py      # google-cloud mock-based GCP tests
│   ├── test_preprocessor.py      # Unit tests for data reduction
│   ├── test_reports.py           # Unit tests for HTML/Markdown generators
│   ├── test_models.py            # Dataclass tests
│   ├── test_cost.py              # Cost estimation tests
│   └── test_port_scanner.py      # nmap XML parser tests
├── terraform/                    # AWS deployment (ECS Fargate)
│   ├── main.tf
│   ├── variables.tf
│   ├── modules/
│   │   ├── ecs/                  # ECS cluster + task definition
│   │   ├── ecr/                  # Container registry
│   │   ├── iam/                  # Task execution roles
│   │   ├── storage/              # S3 + CloudWatch + SSM for API key
│   │   └── scheduler/            # EventBridge Scheduler for periodic runs
│   └── gcp/                      # GCP deployment (Cloud Run Job)
│       ├── main.tf               # Cloud Run Job, Artifact Registry, GCS, Secret Manager
│       ├── variables.tf
│       ├── providers.tf
│       └── outputs.tf
├── Dockerfile                    # Ubuntu 24.04 + Python + gcloud CLI + nmap
├── start.sh                      # Entrypoint: run CLI then upload reports to GCS
├── requirements.txt
├── requirements-dev.txt
├── deploy.sh                     # AWS build-push-deploy helper
└── wizard.sh                     # Unified wizard: scan OR deploy (AWS + GCP + External)
```

---

## Core Data Models

Good data models make the whole system coherent. Here's what `assessment/models.py` contains:

```python
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass
class Finding:
    id: str
    title: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: str          # module name (iam, s3, ec2, ...)
    description: str
    evidence: str
    remediation: str
    resource: Optional[str] = None
    provider: str = "aws"
    references: list = field(default_factory=list)

@dataclass
class ModuleResult:
    module_name: str
    provider: str
    raw_output: dict
    findings: list[Finding] = field(default_factory=list)
    error: Optional[str] = None
    module_risk_score: int = 0
    module_summary: str = ""
    duration_seconds: float = 0.0
    input_tokens: int = 0         # Claude API tokens used for this module
    output_tokens: int = 0

@dataclass
class AttackChain:
    title: str
    steps: list[str]
    findings_involved: list[str]
    likelihood: str = "MEDIUM"    # HIGH | MEDIUM | LOW
    impact: str = "MEDIUM"

@dataclass
class Report:
    scan_id: str
    timestamp: datetime
    provider: str
    account_id: str
    regions: list[str]
    mode: str
    module_results: list[ModuleResult]
    findings: list[Finding]
    attack_chains: list[AttackChain]
    top_10_priorities: list[str]
    recommended_immediate_actions: list[str]
    overall_risk_rating: str
    overall_risk_score: int
    executive_summary: str
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    estimated_cost_usd: float = 0.0
    model_used: str = ""
```

The key insight: `token tracking is first-class`. Every `ModuleResult` tracks how many Claude API tokens it consumed. This means your report always tells you exactly what the AI analysis cost.

---

## The AWS Scanner Layer

Every scanner — AWS and GCP alike — inherits from `BaseScanner`:

```python
class BaseScanner(ABC):
    name: str       # "iam", "s3", "ec2", ...
    provider: str   # "aws", "external"

    @abstractmethod
    def _scan(self) -> tuple[dict, list]:
        """Returns (raw_output_dict, list_of_errors)"""

    def scan(self) -> ModuleResult:
        start = time.time()
        try:
            raw_output, errors = self._scan()
            return ModuleResult(
                module_name=self.name,
                provider=self.provider,
                raw_output=raw_output,
                duration_seconds=time.time() - start,
            )
        except Exception as e:
            return ModuleResult(
                module_name=self.name,
                provider=self.provider,
                raw_output={},
                error=str(e),
                duration_seconds=time.time() - start,
            )
```

Scanners run in parallel via `ThreadPoolExecutor`. A scanner failure never stops other scanners.

### IAM Scanner: The Most Important One

IAM is where most cloud breaches start. Here's what `iam.py` checks:

**Root account**:
```python
def _check_root_account(iam) -> dict:
    """Check root account security posture via credential report."""
    iam.generate_credential_report()
    content = None
    for _ in range(12):
        try:
            resp = iam.get_credential_report()
            content = resp["Content"].decode("utf-8")
            break
        except iam.exceptions.ReportNotPresent:
            time.sleep(0.5)
    if content is None:
        return {"error": "credential report not ready after retries"}
    # Parse CSV credential report
    header = lines[0].split(",")
    root_row = lines[1].split(",")
    data = dict(zip(header, root_row))
    return {
        "mfa_active": data.get("mfa_active") == "true",
        "access_key_1_active": data.get("access_key_1_active") == "true",
        "access_key_2_active": data.get("access_key_2_active") == "true",
        "password_last_used": data.get("password_last_used", "N/A"),
    }
```

**Per-user details** — MFA status, access key age (critical if >180 days), attached policies, inline policies, group memberships.

**Overprivileged roles** — checks both attached managed policies (AdministratorAccess, IAMFullAccess, PowerUserAccess, EC2FullAccess, S3FullAccess) and trust policies allowing `Principal: "*"`.

### S3 Scanner: The Breach Surface

S3 misconfigurations are the #1 source of data breaches. The scanner checks:
- Public access block settings at both bucket and account level
- ACL grants to AllUsers/AuthenticatedUsers
- Bucket policies with `Principal: "*"` and no conditions
- Encryption (SSE-S3, SSE-KMS, or none)
- Versioning and MFA delete
- Server access logging

One important implementation detail: boto3 exception attribute accessors can fail for less common errors. Always use `ClientError` with code checking:

```python
# WRONG — can throw AttributeError if moto/boto3 doesn't have this exception:
except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:

# RIGHT — works everywhere:
from botocore.exceptions import ClientError
...
except ClientError as e:
    code = e.response["Error"]["Code"]
    if code == "ServerSideEncryptionConfigurationNotFoundError":
        info["encryption"] = "none"
```

This is a subtle but important bug. We discovered it during testing with moto.

### Lambda Scanner: The Hidden Attack Surface

Lambda functions are often overlooked in security reviews:

```python
class LambdaScanner(BaseScanner):
    def _scan(self):
        lmb = self.session.client("lambda", region_name=self.region)
        functions = []
        paginator = lmb.get_paginator("list_functions")

        for page in paginator.paginate():
            for fn in page["Functions"]:
                info = {
                    "name": fn["FunctionName"],
                    "runtime": fn.get("Runtime", "unknown"),
                    "role": fn.get("Role", ""),
                    "kms_key_arn": fn.get("KMSKeyArn", ""),  # env var encryption
                    "vpc_config": fn.get("VpcConfig", {}),
                }

                # Check for public function URLs (auth_type=NONE is critical)
                try:
                    url_config = lmb.get_function_url_config(FunctionName=fn["FunctionName"])
                    info["function_url"] = {
                        "url": url_config.get("FunctionUrl", ""),
                        "auth_type": url_config.get("AuthType", ""),
                        "is_public": url_config.get("AuthType") == "NONE",
                    }
                except ClientError:
                    info["function_url"] = None

                functions.append(info)

        return {"functions": functions}, []
```

Key things Lambda scanner flags:
- **Deprecated runtimes**: python3.7 and earlier, nodejs14 and earlier — these are EOL and may have unpatched CVEs
- **Public Function URLs with no auth** — anyone on the internet can invoke your Lambda
- **Unencrypted environment variables** — if your function has DB passwords in env vars, they're visible to anyone with IAM read access unless KMS-encrypted
- **No VPC placement** — Lambda functions handling sensitive data should run inside a VPC

### EKS Scanner: The Kubernetes Layer

```python
class EKSScanner(BaseScanner):
    DEPRECATED_K8S_VERSIONS = {"1.23", "1.24", "1.25", "1.26", "1.27"}

    def _scan(self):
        eks = self.session.client("eks", region_name=self.region)
        clusters = []

        for cluster_name in eks.list_clusters()["clusters"]:
            cluster = eks.describe_cluster(name=cluster_name)["cluster"]

            endpoint_config = cluster.get("resourcesVpcConfig", {})
            logging_config = cluster.get("logging", {}).get("clusterLogging", [])

            enabled_log_types = []
            for lc in logging_config:
                if lc.get("enabled"):
                    enabled_log_types.extend(lc.get("types", []))

            clusters.append({
                "name": cluster_name,
                "version": cluster.get("version", ""),
                "endpoint_public_access": endpoint_config.get("endpointPublicAccess", True),
                "endpoint_public_access_cidrs": endpoint_config.get("publicAccessCidrs", []),
                "audit_logging_enabled": "audit" in enabled_log_types,
                "api_logging_enabled": "api" in enabled_log_types,
                "secrets_encryption": bool(cluster.get("encryptionConfig")),
            })
```

---

## The GCP Scanner Layer

GCP scanners use the `google-cloud-*` Python client libraries and Application Default Credentials (ADC). The same `BaseScanner` contract applies — `_scan()` returns `(raw_output_dict, errors_list)` and failures are isolated.

### GCP IAM Scanner

GCP IAM is structurally different from AWS: permissions are attached to resources (projects, buckets, topics) via *bindings* rather than to identities. The scanner checks both directions:

```python
class GCPIAMScanner(BaseScanner):
    def _scan(self):
        from googleapiclient import discovery
        crm = discovery.build("cloudresourcemanager", "v1")
        iam = discovery.build("iam", "v1")

        # Project-level IAM bindings — who has what role on the whole project
        policy = crm.projects().getIamPolicy(resource=self.project).execute()
        bindings = policy.get("bindings", [])

        risky_roles = [
            "roles/owner", "roles/editor",
            "roles/iam.securityAdmin", "roles/iam.roleAdmin",
            "roles/resourcemanager.projectIamAdmin",
        ]

        risky_bindings = []
        for b in bindings:
            role = b["role"]
            members = b.get("members", [])
            for member in members:
                if role in risky_roles:
                    risky_bindings.append({
                        "member": member,
                        "role": role,
                        "is_service_account": member.startswith("serviceAccount:"),
                        "is_public": member in ("allUsers", "allAuthenticatedUsers"),
                    })

        # Service account key age — user-managed keys older than 90 days are risky
        sa_list = iam.projects().serviceAccounts().list(
            name=f"projects/{self.project}"
        ).execute().get("accounts", [])

        stale_keys = []
        for sa in sa_list:
            keys = iam.projects().serviceAccounts().keys().list(
                name=sa["name"], keyTypes=["USER_MANAGED"]
            ).execute().get("keys", [])
            for key in keys:
                created = datetime.fromisoformat(
                    key["validAfterTime"].replace("Z", "+00:00")
                )
                age_days = (datetime.now(timezone.utc) - created).days
                if age_days > 90:
                    stale_keys.append({
                        "service_account": sa["email"],
                        "key_id": key["name"].split("/")[-1],
                        "age_days": age_days,
                    })

        return {
            "risky_bindings": risky_bindings,
            "stale_service_account_keys": stale_keys,
            "total_bindings": len(bindings),
        }, []
```

Key GCP IAM risks the scanner flags:
- **`roles/owner` or `roles/editor`** on a project — wildcard permissions, equivalent to `*:*` in AWS
- **`allUsers` or `allAuthenticatedUsers`** members — makes resources public to the internet
- **User-managed service account keys older than 90 days** — long-lived credentials that should be rotated
- **`roles/iam.serviceAccountTokenCreator`** — allows impersonating other service accounts

### GCP Compute Scanner

```python
class GCPComputeScanner(BaseScanner):
    def _scan(self):
        from googleapiclient import discovery
        compute = discovery.build("compute", "v1")

        instances = []
        agg = compute.instances().aggregatedList(project=self.project).execute()
        for zone_data in agg.get("items", {}).values():
            for inst in zone_data.get("instances", []):
                metadata_items = {
                    m["key"]: m.get("value", "")
                    for m in inst.get("metadata", {}).get("items", [])
                }
                instances.append({
                    "name": inst["name"],
                    "zone": inst["zone"].split("/")[-1],
                    # OS Login disabled = SSH keys in metadata (risky)
                    "os_login_enabled": metadata_items.get(
                        "enable-oslogin", "false") == "true",
                    # Serial port gives console access without SSH
                    "serial_port_enabled": metadata_items.get(
                        "serial-port-enable", "0") == "1",
                    # Default SA with editor scope = overprivileged
                    "default_service_account": any(
                        "compute@developer" in sa.get("email", "")
                        for sa in inst.get("serviceAccounts", [])
                    ),
                    "public_ip": bool(
                        inst.get("networkInterfaces", [{}])[0]
                            .get("accessConfigs", [])
                    ),
                })

        # Firewall rules — flag rules allowing 0.0.0.0/0 to sensitive ports
        SENSITIVE_PORTS = {22, 3389, 5432, 3306, 27017, 6379, 9200}
        fw_rules = compute.firewalls().list(project=self.project).execute()
        risky_rules = []
        for rule in fw_rules.get("items", []):
            if rule.get("direction") == "INGRESS" and not rule.get("disabled"):
                sources = rule.get("sourceRanges", [])
                if "0.0.0.0/0" in sources or "::/0" in sources:
                    for allowed in rule.get("allowed", []):
                        for port in allowed.get("ports", []):
                            pnum = int(port.split("-")[0])
                            if pnum in SENSITIVE_PORTS:
                                risky_rules.append({
                                    "rule_name": rule["name"],
                                    "port": port,
                                    "protocol": allowed["IPProtocol"],
                                })

        return {"instances": instances, "risky_firewall_rules": risky_rules}, []
```

### GCP Storage Scanner

GCS buckets are the GCP equivalent of S3 — and just as commonly misconfigured:

```python
class GCPStorageScanner(BaseScanner):
    def _scan(self):
        from google.cloud import storage
        client = storage.Client(project=self.project)

        buckets = []
        for bucket in client.list_buckets():
            b = client.get_bucket(bucket.name)
            policy = b.get_iam_policy(requested_policy_version=3)

            is_public = any(
                member in ("allUsers", "allAuthenticatedUsers")
                for binding in policy.bindings
                for member in binding["members"]
            )

            buckets.append({
                "name": b.name,
                "public_access": is_public,
                # Uniform access = no per-object ACLs (recommended)
                "uniform_bucket_level_access":
                    b.iam_configuration.uniform_bucket_level_access_enabled,
                "versioning_enabled": b.versioning_enabled,
                "default_kms_key": b.default_kms_key_name,
                "logging_enabled": bool(b.logging),
                "retention_policy": b.retention_policy_effective_time is not None,
            })

        return {"buckets": buckets, "total": len(buckets)}, []
```

What it flags: public buckets (`allUsers` binding), uniform bucket-level access disabled (allows per-object ACL overrides), no versioning, no CMEK encryption, no access logging.

### GCP Secret Manager & Logging Scanners

**Secret Manager** checks for secrets with no rotation policy, secrets accessible to overly-broad principals, and secret versions that haven't been rotated in over 90 days.

**Cloud Logging** checks the audit log configuration — the most commonly missed GCP security gap:
- **Data Access audit logs disabled** — by default GCP does *not* log read/write access to data (e.g., who read what from GCS or Secret Manager). These must be explicitly enabled and are a critical compliance requirement for SOC 2, PCI DSS, and ISO 27001.
- **No log export sink** — Cloud Logging's default retention is 30 days. Without a sink to GCS or a SIEM, forensic evidence disappears.
- **Admin Activity logs** — cannot be disabled, but the scanner verifies a log sink is actually capturing them outside of Cloud Logging.

```python
def _check_data_access_logs(project: str) -> dict:
    from googleapiclient import discovery
    crm = discovery.build("cloudresourcemanager", "v1")
    policy = crm.projects().getIamPolicy(resource=project).execute()

    audit_configs = policy.get("auditConfigs", [])
    data_access_enabled = any(
        any(alc.get("logType") == "DATA_READ"
            for alc in ac.get("auditLogConfigs", []))
        for ac in audit_configs
    )
    return {
        "data_access_logging_enabled": data_access_enabled,
        "audit_config_count": len(audit_configs),
    }
```

---

## The AI Layer: Where the Magic Happens

### Preprocessing: Don't Send Everything to Claude

Raw cloud scanner output can be enormous — a large IAM scan returns megabytes of JSON. Sending everything to Claude is expensive and hits context limits. The preprocessor reduces data to security-relevant signals:

```python
def preprocess(module_name: str, raw_output: dict, max_chars: int = 40_000) -> str:
    handlers = {
        "iam": _process_iam,
        "s3": _process_s3,
        "ec2": _process_ec2,
        "lambda": _process_lambda,
        "kms": _process_kms,
        "secretsmanager": _process_secrets_manager,
        "eks": _process_eks,
    }
    handler = handlers.get(module_name)
    data = handler(raw_output) if handler else raw_output

    result = json.dumps(data, default=str)
    if len(result) > max_chars:
        logger.warning(
            f"[preprocessor] {module_name} output truncated: "
            f"{len(result):,} → {max_chars:,} chars"
        )
        result = result[:max_chars]
    return result
```

Each handler adds `_issues` annotations to highlight what's wrong:

```python
def _process_lambda(raw: dict) -> dict:
    functions = raw.get("functions", [])
    processed = []
    for fn in functions:
        issues = []
        runtime = fn.get("runtime", "")
        if runtime in DEPRECATED_LAMBDA_RUNTIMES:
            issues.append(f"deprecated runtime: {runtime}")

        url = fn.get("function_url") or {}
        if url.get("is_public"):
            issues.append(f"public function URL with no auth: {url.get('url', '')}")

        if not fn.get("kms_key_arn"):
            issues.append("environment variables not KMS-encrypted")

        if not fn.get("vpc_config", {}).get("VpcId"):
            issues.append("not in VPC")

        fn["_issues"] = issues
        if issues:  # Only include functions with issues
            processed.append(fn)

    return {"functions_with_issues": processed, "total_functions": len(functions)}
```

This reduces a 100-function Lambda scan from 800KB to maybe 15KB, while preserving everything Claude needs.

### The Two-Stage AI Pipeline

**Stage 1: Per-module analysis**

```python
def analyze_modules(module_results, account_id, region, mode, model) -> dict:
    total_usage = {"input_tokens": 0, "output_tokens": 0}

    for mr in module_results:
        if mr.error:
            continue

        scan_data = preprocess(mr.module_name, mr.raw_output)

        user_content = MODULE_ANALYSIS_PROMPT.format(
            module_name=mr.module_name,
            provider=mr.provider,
            account_id=account_id,
            region=region,
            mode=mode,
            scan_output=scan_data,
        )

        try:
            response_text, usage = call_claude(
                model=model,
                system=SYSTEM_PROMPT,
                user_content=user_content,
            )
            data = json.loads(response_text)

            mr.findings = [
                Finding(
                    id=f"{mr.module_name}_{f['id']}",
                    title=f["title"],
                    severity=f["severity"],
                    category=f.get("category", mr.module_name),
                    description=f["description"],
                    evidence=f.get("evidence", ""),
                    remediation=f.get("remediation", ""),
                    resource=f.get("resource"),
                    provider=mr.provider,
                )
                for f in data.get("findings", [])
            ]
            mr.module_risk_score = data.get("module_risk_score", 0)
            mr.module_summary = data.get("module_summary", "")
            mr.input_tokens = usage.get("input_tokens", 0)
            mr.output_tokens = usage.get("output_tokens", 0)

            total_usage["input_tokens"] += mr.input_tokens
            total_usage["output_tokens"] += mr.output_tokens

        except Exception as e:
            logger.error(f"[analyzer] {mr.module_name} analysis failed: {e}")
            # Continue — don't let one module failure stop the whole run

    return total_usage
```

**Stage 2: Synthesis**

The synthesis prompt provides Claude with:
- All module summaries (prose descriptions)
- All findings as JSON
- Counts by severity

And asks for:
- **2-5 attack chains** — specific, realistic scenarios with finding IDs
- **Top 10 priorities** — by actual exploitability, not just severity
- **Executive summary** — 3-5 paragraphs for a CISO audience
- **Overall risk rating** — CRITICAL/HIGH/MEDIUM/LOW with justification
- **5 immediate actions** — specific CLI commands or console steps

The synthesis prompt explicitly asks Claude to be specific:

```
Attack chains should name actual resources: "public S3 bucket `prod-uploads` +
overprivileged IAM role `ecs-task-role` + IMDSv1 enabled on instance `i-0abc123`
creates a path for SSRF-based credential theft and full account takeover"
```

### The System Prompt: Making Claude a Security Expert

```python
SYSTEM_PROMPT = """You are a senior cloud security engineer performing an authorized
vulnerability assessment. You are analyzing raw security scan data collected from a
cloud environment.

Rules:
- Be specific: cite exact resource names, ARNs, policy names, and configuration values
- Assign severity:
  * CRITICAL: actively exploitable, public exposure, no auth required, or active attacker evidence
  * HIGH: significant misconfiguration likely to be exploited in targeted attack
  * MEDIUM: defense-in-depth failure, increases blast radius if other controls fail
  * LOW: best-practice deviation, low exploitability
  * INFO: informational, no direct security impact
- For each finding provide: title, severity, description, evidence (exact data from scan),
  remediation (specific command, console action, or Terraform/CLI change)
- Do not invent findings not supported by the data
- Consider the combination of findings, not just each in isolation
- Output valid JSON exactly matching the provided schema"""
```

The key instruction: "Do not invent findings not supported by the data." This prevents Claude from hallucinating security issues.

---

## The Report Layer

### HTML Report with Live Search

The HTML report is self-contained — no CDN dependencies, works offline. Key features:

**Live search** — filters findings as you type:
```javascript
function filterFindings(query) {
    const q = query.toLowerCase();
    document.querySelectorAll('.finding-card').forEach(card => {
        const text = card.textContent.toLowerCase();
        card.style.display = text.includes(q) ? '' : 'none';
    });
}
```

**Severity filter buttons** — click CRITICAL to show only critical findings.

**Attack chain visualization** — each chain shows steps, likelihood badge, impact badge, and which finding IDs are involved.

**Cost bar** — shows model used, input/output tokens, estimated cost:
```
claude-sonnet-4-6 | 45,230 in / 8,102 out tokens | Est. cost: $0.0847
```

**XSS-safe output** — all user data passes through `_esc()`:
```python
def _esc(s) -> str:
    if s is None:
        return ""
    return (str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;"))
```

### Markdown Report

The Markdown report is designed for:
- Pasting into JIRA/Linear tickets
- Committing to a security findings repo in git
- Sharing in Slack or Confluence

```markdown
# Cloud Security Assessment

**Scan ID:** abc12345
**Date:** 2025-03-11 12:00 UTC
**Provider:** AWS — Account 123456789012
**Regions:** us-east-1
**Mode:** both
**AI Model:** claude-sonnet-4-6 — 45,230 in / 8,102 out tokens — Est. cost: $0.0847

## Overall Risk: 🔴 HIGH (72/100)

> This account has critical security issues requiring immediate attention.
> Root account MFA is disabled. Three S3 buckets are publicly accessible.
> ...

## Immediate Actions

1. Enable MFA on the root account immediately
2. Block public access on S3 bucket `prod-uploads`
...
```

---

## Testing Strategy: 125 Tests, Zero Cloud Calls

### Test Architecture

```
tests/
├── test_models.py          # Pure unit tests — no AWS, no mocks needed
├── test_cost.py            # Cost estimation math
├── test_port_scanner.py    # nmap XML parser
├── test_preprocessor.py    # Data reduction logic
├── test_reports.py         # HTML/Markdown generators with fixture data
└── test_aws_scanners.py    # boto3 API calls mocked with moto
```

### Using moto for AWS Mocking

[moto](https://docs.getmoto.org/) intercepts boto3 API calls and returns realistic responses without hitting AWS. Example:

```python
from moto import mock_aws
import boto3

@mock_aws
def test_iam_detects_missing_root_mfa():
    session = boto3.Session(region_name="us-east-1")
    # No setup needed — moto starts with root MFA disabled by default
    from assessment.scanners.aws.iam import IAMScanner
    result = IAMScanner(session=session, region="us-east-1").scan()
    root = result.raw_output["root_account"]
    assert root["mfa_active"] is False

@mock_aws
def test_s3_detects_encryption_disabled():
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")
    # No encryption configured — moto returns NoSuchEncryptionConfiguration
    from assessment.scanners.aws.s3 import S3Scanner
    result = S3Scanner(session=session, region="us-east-1").scan()
    buckets = result.raw_output["buckets"]
    assert len(buckets) == 1
    assert buckets[0]["encryption"] == "none"
```

**Important moto gotcha**: moto doesn't pre-populate AWS managed policies. If you want to test `AdministratorAccess` attachment, create it first:

```python
@mock_aws
def test_iam_detects_admin_policy_attachment():
    import json
    from unittest.mock import patch
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")

    # Create customer-managed policy (moto can't create managed AWS policies)
    resp = iam.create_policy(
        PolicyName="AdministratorAccess",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }),
    )
    policy_arn = resp["Policy"]["Arn"]
    iam.create_user(UserName="adminuser")
    iam.attach_user_policy(UserName="adminuser", PolicyArn=policy_arn)

    # Patch the config constant to use our test ARN
    with patch("assessment.scanners.aws.iam.OVERPRIVILEGED_MANAGED_POLICIES", [policy_arn]):
        from assessment.scanners.aws.iam import IAMScanner
        result = IAMScanner(session=session, region="us-east-1").scan()

    admin_attachments = result.raw_output["attached_admin_policies"]
    assert any(a["name"] == "adminuser" for a in admin_attachments)
```

### Testing Report Generators Without AWS

For HTML/Markdown tests, we build fixture data and test the output directly:

```python
def _make_report(**kwargs) -> Report:
    """Create a minimal but valid Report for testing."""
    return Report(
        scan_id="abc12345",
        timestamp=datetime(2025, 3, 11, 12, 0, 0, tzinfo=timezone.utc),
        provider="aws",
        account_id="123456789012",
        ...
    )

class TestGenerateHTML:
    def test_xss_escape_in_account_id(self):
        report = _make_report()
        report.account_id = '<script>alert("xss")</script>'
        html = generate_html(report)
        # Payload must be escaped, not executed
        assert 'alert("xss")' not in html
        assert "&lt;script&gt;" in html

    def test_contains_cost_info(self):
        html = generate_html(_make_report())
        assert "claude-sonnet-4-6" in html
        assert "0.0480" in html
```

### Test Coverage

```
tests/test_models.py          18 tests  — dataclass defaults, token fields
tests/test_cost.py            10 tests  — pricing math, model fallback
tests/test_port_scanner.py    12 tests  — nmap XML parsing
tests/test_preprocessor.py    45 tests  — all module handlers, edge cases
tests/test_reports.py         33 tests  — HTML generator, Markdown, _esc()
tests/test_aws_scanners.py    30 tests  — IAM, S3, EC2, Lambda, KMS, SecretsManager
─────────────────────────────────────────
Total: 125 tests, 0 failures
```

Run them:
```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

---

## Deployment: AWS ECS on Fargate

For teams that want automated, scheduled assessments without running anything locally.

### Architecture

```
EventBridge Scheduler
       │
       ▼
ECS Task (Fargate)
  ├── Container: stratus-ai (from ECR)
  ├── IAM Role: read-only + specific write to S3/CloudWatch
  ├── Env: ANTHROPIC_API_KEY_SSM=/stratus-ai/anthropic-key
  └── Reports → S3 bucket + CloudWatch Logs
```

The Anthropic API key is never stored in container environment variables. Instead, the ECS task role has permission to read an SSM Parameter Store SecureString, and the CLI resolves it at startup:

```python
def _resolve_anthropic_key() -> str:
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if key:
        return key

    ssm_name = os.environ.get("ANTHROPIC_API_KEY_SSM", "")
    if ssm_name:
        ssm = boto3.client("ssm")
        resp = ssm.get_parameter(Name=ssm_name, WithDecryption=True)
        return resp["Parameter"]["Value"]

    return ""
```

### Terraform Setup

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your settings:
#   anthropic_api_key = "sk-ant-..."
#   name_prefix       = "stratus-ai"
#   aws_region        = "us-east-1"

terraform init
terraform plan
terraform apply
```

This creates:
- **ECR repository** for the Docker image
- **S3 bucket** for reports (versioned, lifecycle policy, CloudWatch logging)
- **SSM Parameter** `/stratus-ai/anthropic-key` (SecureString, KMS-encrypted)
- **IAM roles** — execution role + task role with read-only AWS permissions + S3/SSM write
- **ECS cluster** + task definition
- **EventBridge Scheduler** (optional) for weekly runs

### Minimal Terraform Example

```hcl
# terraform/examples/minimal/main.tf
module "stratus_ai" {
  source = "../../"

  name_prefix       = "stratus-ai"
  aws_region        = "us-east-1"
  anthropic_api_key = var.anthropic_api_key

  # Use your existing VPC, or let the module find the default VPC
  vpc_id     = ""
  subnet_ids = []

  enable_scheduler = false   # run manually via ECS RunTask
}
```

### Scheduled Example

```hcl
# terraform/examples/scheduled/main.tf
module "stratus_ai" {
  source = "../../"

  name_prefix       = "stratus-ai"
  aws_region        = "us-east-1"
  anthropic_api_key = var.anthropic_api_key

  enable_scheduler        = true
  schedule_expression     = "cron(0 6 ? * MON *)"  # Every Monday at 6am UTC
  schedule_timezone       = "UTC"
  assessment_extra_args   = "--mode internal --severity HIGH"

  report_retention_days   = 90
  ecr_retention_count     = 10
}
```

### Deploying a New Image

```bash
# Build and push to ECR
./deploy.sh

# Or manually:
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com

docker build -t stratus-ai .
docker tag stratus-ai:latest <account>.dkr.ecr.us-east-1.amazonaws.com/stratus-ai:latest
docker push <account>.dkr.ecr.us-east-1.amazonaws.com/stratus-ai:latest
```

### Running On-Demand from AWS Console or CLI

```bash
aws ecs run-task \
  --cluster stratus-ai \
  --task-definition stratus-ai \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={
    subnets=[subnet-abc123],
    securityGroups=[sg-xyz789],
    assignPublicIp=ENABLED
  }" \
  --overrides '{
    "containerOverrides": [{
      "name": "stratus-ai",
      "command": ["--mode", "internal", "--severity", "MEDIUM"]
    }]
  }'
```

The task runs for 5-15 minutes depending on account size, uploads reports to S3, and terminates.

---

## Deployment: GCP Cloud Run Job

For GCP, StratusAI runs as a **Cloud Run Job** — a serverless batch container that starts on demand or on a Cloud Scheduler cron, runs to completion, and stops. No always-on infra, no servers to manage.

### GCP Architecture

```
Cloud Scheduler (cron)
       │
       ▼
Cloud Run Job  ──────────────────────────────────────────────────┐
  ├── Image: Artifact Registry (us-central1-docker.pkg.dev/...)  │
  ├── Service Account: stratusai-runner                          │
  │     ├── roles/viewer on scan target project                  │
  │     ├── roles/storage.objectCreator on reports bucket        │
  │     └── roles/secretmanager.secretAccessor on API key secret │
  ├── Env: GOOGLE_CLOUD_PROJECT, OUTPUT_GCS_BUCKET               │
  └── Secret: AI API key → Secret Manager → env var at runtime   │
       │
       ▼                                                          │
  start.sh runs:                                                  │
    python -m assessment.cli --provider gcp ...                   │
    gsutil cp /tmp/output/* gs://<bucket>/reports/  ◄────────────┘
```

One non-obvious design point: Cloud Run's filesystem is ephemeral — files written during the job are gone when the container exits. The `start.sh` entrypoint wrapper solves this by running `gsutil cp` to upload `/tmp/output/*` to GCS immediately after the CLI completes.

### GCP Terraform Setup

```bash
cd terraform/gcp
cp terraform.tfvars.example terraform.tfvars
# Fill in: gcp_project, gcp_region, api_key (your AI provider key)

terraform init
terraform apply
```

This creates (in one `terraform apply`):

| Resource | Purpose |
|---|---|
| `google_artifact_registry_repository` | Docker image registry |
| `google_storage_bucket` | Report storage with versioning + lifecycle |
| `google_secret_manager_secret` | AI API key, never in env vars |
| `google_service_account` runner | Least-privilege identity for the job |
| `google_cloud_run_v2_job` | The scanner job definition |
| `google_cloud_scheduler_job` | Optional: cron trigger |

Key Terraform design decisions:

**Dynamic API key env var name** — the correct environment variable (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GOOGLE_API_KEY`) is selected at plan time based on the model name prefix:

```hcl
locals {
  api_key_env_name = (
    can(regex("^claude-", var.ai_model))          ? "ANTHROPIC_API_KEY" :
    can(regex("^(gpt-|o1|o3|o4)", var.ai_model))  ? "OPENAI_API_KEY"    :
    can(regex("^gemini-", var.ai_model))           ? "GOOGLE_API_KEY"    :
    "ANTHROPIC_API_KEY"
  )
}
```

**`args` not `command` in Cloud Run Job** — this is a common mistake. In Terraform's `google_cloud_run_v2_job`, `command` overrides the Docker `ENTRYPOINT` (the binary itself). `args` passes flags to the existing entrypoint. Using `command = ["--provider", "gcp"]` would try to execute `--provider` as a binary and crash immediately:

```hcl
containers {
  image = local.full_image
  args  = local.cli_args   # ← correct: passes flags to start.sh
  # command = ...          # ← wrong: would override the entrypoint
}
```

### Two-Phase Deploy with the Wizard

The unified `wizard.sh` handles the full GCP deployment when you pick **"Deploy infrastructure"** at the opening menu:

```bash
./wizard.sh
# Step 0: Choose an action:
#   1) Run a scan now
#   2) Deploy infrastructure   ← pick this
```

There's a chicken-and-egg problem with GCP deployments: Cloud Run validates the Docker image at job creation time, but the image can't be pushed until the Artifact Registry repository exists. The wizard solves this with a two-phase apply:

```
Phase 1: terraform apply -target=google_project_service.apis
                         -target=google_artifact_registry_repository.images
         → Creates only the registry and enables APIs

docker build -t <region>-docker.pkg.dev/<project>/stratusai/stratusai:latest .
docker push  <region>-docker.pkg.dev/<project>/stratusai/stratusai:latest
         → Pushes image to the now-existing registry

Phase 2: terraform apply
         → Creates Cloud Run Job, GCS bucket, Secret Manager, Scheduler
         → Image now exists, so Cloud Run validation passes
```

The wizard also:
- Fetches and lists all accessible GCP projects so you pick by number (both for the deploy-into project and the scan target)
- Reads AI API keys from your environment (no re-entry if already set)
- Verifies `gcloud` auth and ADC before starting
- Supports scanning a *different* project than the one you deploy into
- Optionally triggers an immediate scan after deploy
- Cleans up the GCS bucket before `terraform destroy` (avoiding the "bucket not empty" error)

### Running GCP Scans On-Demand

```bash
# Trigger via gcloud
gcloud run jobs execute stratusai-scan \
  --region us-central1 \
  --project my-gcp-project

# Watch logs in real time
gcloud logging read \
  'resource.type=cloud_run_job AND resource.labels.job_name=stratusai-scan' \
  --project my-gcp-project \
  --limit 100 \
  --format "value(textPayload)"

# List completed executions
gcloud run jobs executions list \
  --job stratusai-scan \
  --region us-central1

# Download latest report from GCS
gsutil cp "gs://my-gcp-project-stratusai-reports/reports/*.html" ./
```

Reports are persisted to `gs://<project>-stratusai-reports/reports/` with versioning enabled and a configurable retention lifecycle (default: 90 days).

---

## Running Locally

### Installation

```bash
git clone https://github.com/your-org/stratus-ai
cd stratus-ai
pip install -r requirements.txt
```

**External scan prerequisites** (optional):
```bash
# Port scanning
sudo apt-get install nmap    # Linux
brew install nmap            # macOS

# SSL analysis
pip install pyOpenSSL
```

### Basic AWS Assessment

```bash
# Configure AWS credentials
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
# Or: aws configure

# Set Anthropic API key
export ANTHROPIC_API_KEY=sk-ant-...

# Run assessment
stratus --provider aws --mode internal

# With external scan too
stratus --provider aws --mode both --target your-domain.com

# Scan all default regions
stratus --provider aws --all-regions

# Run only specific modules
stratus --provider aws --modules iam,s3,ec2

# Skip AI analysis (raw scanner output only, free)
stratus --provider aws --no-ai

# Filter to HIGH+ findings only
stratus --provider aws --severity HIGH

# Add environment context to sharpen AI analysis
stratus --provider aws --context "Production fintech, PCI DSS scope, handles cardholder data"

# Use a different LLM provider
stratus --provider aws --model gpt-4o         # OpenAI (requires OPENAI_API_KEY)
stratus --provider aws --model gemini-2.0-flash  # Google (requires GOOGLE_API_KEY)
stratus --provider aws --model o3-mini        # OpenAI reasoning model

# Upload reports to S3
stratus --provider aws --output-s3 my-security-reports-bucket
```

### GCP Assessment

```bash
# Authenticate (one-time setup)
gcloud auth application-default login

# Basic GCP internal scan
stratus --provider gcp --project my-gcp-project

# With external scan of a public endpoint
stratus --provider gcp --project my-gcp-project \
  --mode both --target api.myapp.com

# Scan only specific GCP modules
stratus --provider gcp --project my-gcp-project \
  --modules iam,compute,storage

# Use Gemini as the AI (stays within Google ecosystem, no extra key needed if using ADC)
stratus --provider gcp --project my-gcp-project \
  --model gemini-2.0-flash

# Filter to HIGH and above
stratus --provider gcp --project my-gcp-project \
  --severity HIGH

# Add context for sharper AI analysis
stratus --provider gcp --project my-gcp-project \
  --context "Production data platform, handles PII, SOC 2 Type II scope"

# Skip AI (raw scanner output only — useful for quick inventory)
stratus --provider gcp --project my-gcp-project --no-ai

# Or use the interactive wizard — lists all your GCP projects by number
./wizard.sh
```

### Sample Output

```
► Running 9 scanner modules...
  Modules: aws/iam, aws/s3, aws/ec2, aws/cloudtrail, aws/rds, aws/lambda, aws/kms, aws/secretsmanager, aws/eks

► Running AI analysis (claude-sonnet-4-6)...
  Analyzing modules...
  [iam] analysis complete — 47 findings considered, 8 findings returned (5,230 in / 1,102 out tokens)
  [s3] analysis complete — 12 findings considered, 6 findings returned (3,841 in / 891 out tokens)
  [ec2] analysis complete — 23 findings considered, 5 findings returned (4,102 in / 734 out tokens)
  ...
  Running synthesis...

► Generating reports...
  HTML:     ./output/report_2025-03-11T12-00-00Z.html
  Markdown: ./output/report_2025-03-11T12-00-00Z.md

╔══════════════════════ SUMMARY ════════════════════════╗
  Overall Risk: HIGH (72/100)
  Provider: AWS — 123456789012
  Findings:
    3 Critical  8 High  12 Medium  6 Low

  Top Action: Enable MFA on root account immediately

  AI Cost: $0.0847 (45,230 in / 8,102 out tokens)
╚════════════════════════════════════════════════════════╝
```

---

## Quick Start with the Wizard

`wizard.sh` is the single entry point for everything: running a scan *or* deploying the infrastructure. Run it once and it guides you through whichever flow you need.

```bash
chmod +x wizard.sh
./wizard.sh
```

The first thing the wizard asks is what you want to do:

```
  Step 0 — What would you like to do?
    1)  Run a scan now        — assess AWS / GCP / external target (local or Docker)
    2)  Deploy infrastructure — set up Cloud Run Job (GCP) or ECS Fargate (AWS) + scheduler

  Enter 1-2 [1]:
```

### Scan path (option 1) — 7 steps

Walks you through a one-off assessment. Takes about 2 minutes to configure.

```
  Step 1 of 7 — Execution Mode
    1)  Docker  (recommended — no local dependencies needed)
    2)  Local Python  (requires: pip install -r requirements.txt)

  Step 2 of 7 — Cloud Provider
    1)  AWS      — Amazon Web Services
    2)  GCP      — Google Cloud Platform
    3)  External — External-only scan (any public hostname, no cloud credentials)

  Step 3 of 7 — Scan Mode
    1)  Internal  — Cloud API scanning (IAM, storage, compute, …)
    2)  External  — Network scanning (ports, TLS, headers, DNS)
    3)  Both      — Internal + external (recommended)

  External target hostname or IP for external scan (Enter to skip): myapp.example.com

  Step 4 of 7 — Cloud Credentials
    # AWS: reads ~/.aws profiles, lets you pick profile + region
    # GCP: checks ADC, then lists all accessible projects by number:

    ▸ Fetching accessible GCP projects...
      1)  my-prod-project-123  —  Production App
      2)  my-staging-4567      —  Staging Environment
      3)  data-pipeline-9999   —  Data Platform
      4)  Enter project ID manually
    Enter 1-4 [1]: 2
  ✓ Selected: my-staging-4567

  Step 5 of 7 — AI Model
    Estimated cost per full scan:
      Gemini 2.0 Flash      ~$0.01   fastest + cheapest
      Claude Haiku 4.5      ~$0.01   fast + cheap
      Claude Sonnet 4.6     ~$0.06   best quality  ← default
      Claude Opus 4.6       ~$0.30   highest quality

    1)  Anthropic  (Claude Sonnet / Haiku / Opus)
    2)  OpenAI     (GPT-4o, GPT-4o mini, o3-mini, o1)
    3)  Google     (Gemini 2.0 Flash, 1.5 Pro, 1.5 Flash)

  Step 6 of 7 — Scan Options
    Minimum severity filter, module selection, environment context, output dir

  Step 7 of 7 — Review
    Prints full configuration summary → asks for confirmation → launches
```

After the scan, the wizard prints clickable `file://` links to every generated report and auto-opens the HTML in your browser:

```
╔══════════════════════════════════════╗
║   Assessment complete!               ║
╚══════════════════════════════════════╝
✓ Reports saved to: /home/user/output/

  Generated reports:
    🌐  file:///home/user/output/report_2026-03-14T10-00-00Z.html
    📄  file:///home/user/output/report_2026-03-14T10-00-00Z.md
    📋  file:///home/user/output/report_2026-03-14T10-00-00Z.json
```

### Deploy path (option 2) — 9 steps

Provisions and deploys the full scheduled-scan infrastructure on AWS (ECS Fargate) or GCP (Cloud Run Job).

**AWS deploy flow:**
```
  Step 1 — Platform:      AWS or GCP
  Step 2 — Dependencies:  verifies aws / docker / terraform are installed
  Step 3 — AWS auth:      lists configured profiles, verifies via STS
  Step 4 — Settings:      region, name prefix, environment label
  Step 5 — Networking:    auto-use default VPC  OR  specify VPC + subnets
                          (lists your VPCs and subnets for easy selection)
  Step 6 — AI model:      pick model + enter API key (reads from env if set)
  Step 7 — Scan config:   regions, severity, external target, modules, context
  Step 8 — Scheduler:     EventBridge rate/cron expression  (e.g. rate(7 days))
  Step 9 — Post-deploy:   optionally trigger an immediate scan
  → writes terraform/terraform.tfvars
  → runs ./deploy.sh
```

**GCP deploy flow:**
```
  Step 1 — Platform:      GCP
  Step 2 — Dependencies:  verifies gcloud / docker / terraform
  Step 3 — GCP auth:      checks active account + Application Default Credentials
  Step 4 — Project:       pick deploy-into project from numbered list + region + prefix
  Step 5 — Scan target:   same project  OR  pick a different project from numbered list
  Step 6 — AI model:      pick model + API key
  Step 7 — Scan config:   severity, external target, modules, context
  Step 8 — Scheduler:     Cloud Scheduler cron  (e.g. 0 8 * * 1 = Mondays at 08:00)
  Step 9 — Post-deploy:   optionally trigger an immediate scan
  → writes terraform/gcp/terraform.tfvars
  → Phase 1: terraform apply (APIs + Artifact Registry only)
  → docker build + push image
  → Phase 2: terraform apply (Cloud Run Job + GCS + Secret Manager + Scheduler)
```

Both deploy paths write a `terraform.tfvars` file, show a full summary before applying, and offer cleanup (destroy) at the end.

### When to use the wizard vs the CLI directly

| Scenario | Use |
|---|---|
| First time running StratusAI | `./wizard.sh` |
| One-off scan, know the flags | `stratus --provider aws ...` |
| Deploying to AWS or GCP | `./wizard.sh` → option 2 |
| CI/CD pipeline | CLI with env vars |
| Sharing a runbook with the team | Wizard — prints full command in Step 7 for copy-paste |

---

## Lessons Learned

### 1. Don't Trust boto3 Exception Attributes

```python
# This looks right but can fail:
except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
    ...

# This always works:
from botocore.exceptions import ClientError
except ClientError as e:
    if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
        ...
```

The boto3 exception factory sometimes doesn't have attributes for less-common error codes. Using `ClientError` + code string comparison is more robust and works identically in production and with moto.

### 2. Preprocess Before Sending to AI

Raw AWS output can be gigabytes. For a 500-function Lambda account, listing all functions returns ~2MB of JSON. Sending that to Claude is expensive and often exceeds context windows.

The preprocessor pattern — annotate issues, filter to only problematic items, truncate with a warning — reduces token costs by 80%+ on large accounts while preserving all security-relevant signal.

### 3. Error Isolation Is Non-Negotiable

If one scanner throws an exception, other scanners must still run. If one module's AI analysis fails (e.g., response isn't valid JSON), other modules must still be analyzed. If synthesis fails, partial results should still produce a report.

Every layer has independent try/except with logging. A failed scanner produces a `ModuleResult` with `error` set but doesn't crash the run.

### 4. Test With Fixtures, Not Live AWS

The entire test suite runs in 11 seconds with zero real AWS API calls. This means:
- Tests run in CI without AWS credentials
- Tests are deterministic — no flaky behavior from AWS rate limiting
- Edge cases (no password policy, no buckets, malformed XML) are easy to test
- You can run tests 100 times during development without cost

### 5. The Synthesis Stage Is Where AI Pays Off

Per-module analysis is useful but not transformative — a rule-based scanner could flag the same individual issues. The synthesis stage is what AI uniquely provides: identifying that *three separate findings across three modules* form an exploitable attack chain that no human reviewer would have connected.

Example synthesis output:
> "Attack Chain: SSRF to Full Account Takeover
>
> Steps: 1) Exploit SSRF in Lambda function `api-processor` via unvalidated user input to HTTP endpoint parameter. 2) Access IMDSv1 metadata endpoint at 169.254.169.254 (EC2 instance `i-0abc123` has IMDSv1 not disabled). 3) Retrieve IAM role credentials for `ecs-task-role` which has `iam:PassRole` and `ec2:*`. 4) Create new IAM user with AdministratorAccess. 5) Full account takeover achieved.
>
> Findings involved: lambda_ssrf_risk, ec2_imdsv1_enabled, iam_role_overprivileged_ecs_task
> Likelihood: HIGH | Impact: CRITICAL"

No traditional scanner produces output like this.

---

## Cost and Performance

### Typical Run Costs

| Account Size | Approx. Tokens | claude-sonnet-4-6 | gpt-4o | gemini-2.0-flash |
|---|---|---|---|---|
| Small (10 users, 5 buckets) | ~20K in / 5K out | $0.02 | $0.02 | $0.004 |
| Medium (50 users, 20 buckets, 100 Lambda) | ~55K in / 12K out | $0.06 | $0.06 | $0.01 |
| Large (200+ users, many services) | ~120K in / 25K out | $0.15 | $0.12 | $0.02 |

The tiered model feature further reduces costs: simple modules (DNS, SSL, KMS, Secrets Manager) are automatically routed to cheaper models — Haiku, gpt-4o-mini, or gemini-flash — saving 30-50% on typical runs without any loss of finding quality.

### Performance

On a medium-sized account with 9 modules:
- Scanner phase: ~30-60 seconds (runs in parallel via ThreadPoolExecutor)
- AI analysis: ~90-180 seconds (sequential per-module, network-bound)
- Report generation: <1 second

Total: 2-4 minutes for a full assessment.

---

## What's Next

Shipped since the initial release:
- **GCP support** — 7 scanner modules (IAM, Compute, Storage, Cloud Functions, Cloud Run, Secret Manager, Logging)
- **Multi-LLM support** — Claude (Anthropic), GPT-4o/o1/o3/o4-mini (OpenAI), Gemini 2.0/1.5 (Google)
- **Tiered model selection** — low-signal modules auto-downgrade to cheaper models (Haiku, gpt-4o-mini, gemini-flash)
- **`--context` flag** — free-text environment description that sharpens AI severity ratings
- **Unified `wizard.sh`** — single interactive wizard for both running scans *and* deploying infrastructure (AWS ECS Fargate or GCP Cloud Run Job); handles auth, Artifact Registry setup, Secret Manager, scheduled runs, and optional immediate post-deploy scan in one flow
- **Numbered GCP project selection** — `wizard.sh` lists all accessible GCP projects on your account so you can pick by number instead of typing a project ID; works for scan target, deploy-into project, and scan target when they differ

Features in progress:

1. **Azure support** — The architecture supports multiple providers; scanner modules are next
2. **Drift detection** — Compare two reports and highlight what changed (new public bucket, new IAM user without MFA)
3. **Remediation automation** — For select finding types, offer `--auto-fix` mode that applies the remediation command
4. **GitHub Actions integration** — Run on every Terraform plan/apply to catch misconfigs before they land
5. **Custom rule support** — YAML-based rules so teams can add company-specific checks
6. **Multi-account scanning** — Use AWS Organizations to scan all accounts in one run

---

## Full Quick-Start Reference

```bash
# Clone and install
git clone https://github.com/your-org/stratus-ai
cd stratus-ai
pip install -r requirements.txt

# Run tests (no cloud credentials needed)
pip install -r requirements-dev.txt
python -m pytest tests/ -v   # 125 passed

# ── AWS ───────────────────────────────────────────────────────────
export AWS_PROFILE=your-profile
export ANTHROPIC_API_KEY=sk-ant-...

stratus --provider aws                                  # internal scan
stratus --provider aws --mode both --target example.com # + external scan
stratus --provider aws --severity HIGH                  # HIGH+ only
stratus --provider aws --model gpt-4o                  # use OpenAI

# Deploy to AWS (ECS Fargate)
cd terraform && cp terraform.tfvars.example terraform.tfvars
vim terraform.tfvars && terraform init && terraform apply
./deploy.sh          # build + push Docker image to ECR

# ── GCP ───────────────────────────────────────────────────────────
gcloud auth application-default login
export ANTHROPIC_API_KEY=sk-ant-...

stratus --provider gcp --project my-gcp-project
stratus --provider gcp --project my-gcp-project --mode both --target api.example.com
stratus --provider gcp --project my-gcp-project --model gemini-2.0-flash

# Deploy to GCP (Cloud Run Job) — wizard handles everything
./wizard.sh          # pick option 2 (Deploy infrastructure) → GCP

# ── Wizard (recommended for first run or deploy) ─────────────────
./wizard.sh          # option 1: scan  |  option 2: deploy to AWS or GCP
```

---

## Conclusion

StratusAI demonstrates what's possible when you combine traditional infrastructure scanning with AI analysis. The individual pieces aren't new: IAM scanning, S3 bucket analysis, nmap port scanning — these have existed for years in tools like ScoutSuite, Prowler, and Steampipe.

The difference is the AI layer:
- **Context-aware analysis**: The LLM understands that "Lambda with SSRF risk + EC2 with IMDSv1 + overprivileged IAM role" is a specific attack path, not three unrelated findings. The same cross-module reasoning applies to GCP: "GCS bucket with `allUsers` + service account with `roles/editor` + metadata server accessible = credential theft path."
- **Intelligent prioritization**: Instead of sorting 400 findings by severity, get a top-10 list ranked by actual exploitability on *your* specific account
- **Human-readable output**: Executive summaries that explain what an attacker could *actually do*, not just that "bucket versioning is disabled" or "Data Access audit logs are not enabled"
- **Specific remediation**: Not "enable encryption" but `aws s3api put-bucket-encryption ...` or `gcloud projects set-iam-policy ... --member=... --role=roles/viewer`
- **Provider and model flexibility**: Scan AWS or GCP; analyze with Claude, GPT-4o, or Gemini — switch with a single `--model` flag. Running a GCP scan with Gemini keeps everything within the Google ecosystem.
- **Serverless deployment on both clouds**: AWS ECS Fargate or GCP Cloud Run Job — deploy once, scan on a schedule, reports land in S3 or GCS automatically

The tool runs locally in 5 minutes, deploys to AWS or GCP for automated weekly runs, costs under $0.15 per assessment (or under $0.02 with Gemini), and produces reports your CISO will actually read.

All code is in the repository. The 125-test suite means you can modify anything with confidence.

---

*All code in this article is from the StratusAI project. The tool is designed for authorized security assessments of AWS and GCP environments you own or have explicit permission to scan.*
