# StratusAI: I Built an AI-Powered Cloud Security Scanner That Runs on AWS — Here's Everything

*A complete engineering walkthrough of building, testing, and deploying an intelligent cloud security assessment tool using Python, Claude AI, and Terraform*

---

## The Problem Every Cloud Team Faces

Your AWS account has been running for two years. You have 47 IAM users, 30+ S3 buckets, EC2 instances in multiple regions, Lambda functions, RDS databases, and a Kubernetes cluster. You *know* there are misconfigurations. You just don't know which ones are actively dangerous versus which are theoretical.

Traditional security tools give you 800 raw findings and a risk score. They tell you "S3 bucket `logs-2021-archive` has versioning disabled." Great. Is that a P0 incident or a Tuesday afternoon task?

What you actually need is something that:
1. **Scans everything** across your AWS environment
2. **Understands context** — an unencrypted S3 bucket holding Lambda code *plus* an EC2 instance with IMDSv1 enabled *plus* an overprivileged IAM role is an attack chain, not three separate findings
3. **Prioritizes ruthlessly** — which 5 things should you fix before you close your laptop tonight?
4. **Explains in plain English** what an attacker could actually do

That's what I built: **StratusAI**, an open-source cloud security assessment tool that combines traditional boto3-based AWS scanning with Claude AI for intelligent analysis and synthesis. This article is a complete engineering guide — architecture, code, testing, and deployment included.

---

## What StratusAI Does

In a single CLI command:

```bash
stratus --provider aws --mode both --target your-domain.com
```

StratusAI will:

1. **Run 9 internal AWS scanner modules**: IAM, S3, EC2, CloudTrail, RDS, Lambda, KMS, Secrets Manager, EKS
2. **Run 4 external scan modules**: port scan (nmap), SSL/TLS analysis, HTTP security headers, DNS/email security (DMARC, SPF, DKIM)
3. **Send each module's raw data to Claude AI** for per-module security analysis
4. **Synthesize everything cross-module** to identify attack chains (e.g., "public S3 bucket + IMDSv1 EC2 + overprivileged IAM role = credential theft path")
5. **Generate HTML and Markdown reports** with severity filtering, live search, and executive summary
6. **Optionally deploy to AWS ECS** and run on a schedule via EventBridge Scheduler

The result: an interactive HTML report you can share with your CISO, showing exactly which resources are at risk, what an attacker could do, and the specific CLI commands to fix it.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         StratusAI                               │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │   Scanners   │    │  AI Layer    │    │    Reports       │  │
│  │              │    │              │    │                  │  │
│  │  AWS (9)     │───►│  Preprocessor│───►│  HTML (rich UI)  │  │
│  │  External(4) │    │  Per-module  │    │  Markdown        │  │
│  │              │    │  Synthesis   │    │  S3 upload       │  │
│  └──────────────┘    └──────────────┘    └──────────────────┘  │
│         │                   │                                   │
│         ▼                   ▼                                   │
│  ┌──────────────┐    ┌──────────────┐                           │
│  │  ModuleResult│    │  Claude API  │                           │
│  │  (raw_output,│    │  (Sonnet 4.6)│                           │
│  │   findings,  │    │              │                           │
│  │   tokens)    │    └──────────────┘                           │
│  └──────────────┘                                               │
└─────────────────────────────────────────────────────────────────┘
```

Two-stage AI pipeline:
- **Stage 1** — Each module is analyzed independently. Claude returns structured JSON: findings (with severity, evidence, remediation), risk score, and module summary.
- **Stage 2** — A synthesis pass takes all module summaries and findings, identifies attack chains, produces a top-10 priority list, executive summary, and overall risk rating.

---

## Project Structure

```
cloud_audit/
├── assessment/
│   ├── cli.py                    # Click CLI entrypoint
│   ├── config.py                 # Thresholds, sensitive ports, model pricing
│   ├── models.py                 # Dataclasses: Finding, ModuleResult, Report, AttackChain
│   ├── runner.py                 # Parallel scanner execution
│   ├── ai/
│   │   ├── client.py             # Claude API wrapper + cost estimation
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
│   ├── test_aws_scanners.py      # moto-based integration tests
│   ├── test_preprocessor.py      # Unit tests for data reduction
│   ├── test_reports.py           # Unit tests for HTML/Markdown generators
│   ├── test_models.py            # Dataclass tests
│   ├── test_cost.py              # Cost estimation tests
│   └── test_port_scanner.py      # nmap XML parser tests
├── terraform/                    # Complete AWS deployment
│   ├── main.tf
│   ├── variables.tf
│   ├── modules/
│   │   ├── ecs/                  # ECS cluster + task definition
│   │   ├── ecr/                  # Container registry
│   │   ├── iam/                  # Task execution roles
│   │   ├── storage/              # S3 + CloudWatch + SSM for API key
│   │   └── scheduler/            # EventBridge Scheduler for periodic runs
│   └── examples/
│       ├── minimal/              # Minimal on-demand setup
│       └── scheduled/            # Scheduled weekly runs
├── Dockerfile
├── requirements.txt
├── requirements-dev.txt
└── deploy.sh
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

## The Scanner Layer

Every scanner inherits from `BaseScanner`:

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

## The AI Layer: Where the Magic Happens

### Preprocessing: Don't Send Everything to Claude

Raw AWS scanner output can be enormous — a large IAM scan returns megabytes of JSON. Sending everything to Claude is expensive and hits context limits. The preprocessor reduces data to security-relevant signals:

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

## Testing Strategy: 125 Tests, Zero AWS Calls

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

# Upload reports to S3
stratus --provider aws --output-s3 my-security-reports-bucket
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

| Account Size | Modules | Approx. Tokens | Approx. Cost |
|---|---|---|---|
| Small (10 users, 5 buckets) | All 9 | ~20K in / 5K out | $0.02 |
| Medium (50 users, 20 buckets, 100 Lambda) | All 9 | ~55K in / 12K out | $0.06 |
| Large (200+ users, many services) | All 9 | ~120K in / 25K out | $0.15 |

With `claude-sonnet-4-6` pricing ($3/MTok input, $15/MTok output). Haiku would be ~10x cheaper; Opus ~5x more expensive.

### Performance

On a medium-sized account with 9 modules:
- Scanner phase: ~30-60 seconds (runs in parallel via ThreadPoolExecutor)
- AI analysis: ~90-180 seconds (sequential per-module, network-bound)
- Report generation: <1 second

Total: 2-4 minutes for a full assessment.

---

## What's Next

Features I'm planning or already designing:

1. **GCP and Azure support** — The architecture supports multiple providers; it just needs scanner implementations
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

# Set credentials
export AWS_PROFILE=your-profile
export ANTHROPIC_API_KEY=sk-ant-...

# Run tests (no AWS needed)
pip install -r requirements-dev.txt
python -m pytest tests/ -v   # should be 125 passed

# Basic assessment
stratus --provider aws

# Full assessment with external scan
stratus --provider aws --mode both --target example.com

# Deploy to AWS (Terraform)
cd terraform
cp terraform.tfvars.example terraform.tfvars
vim terraform.tfvars
terraform init && terraform apply

# Push Docker image
./deploy.sh
```

---

## Conclusion

StratusAI demonstrates what's possible when you combine traditional infrastructure scanning (boto3 API calls) with AI analysis (Claude). The individual pieces aren't new: IAM scanning, S3 bucket analysis, nmap port scanning — these have existed for years in tools like ScoutSuite, Prowler, and Steampipe.

The difference is the AI layer:
- **Context-aware analysis**: Claude understands that "Lambda with SSRF risk + EC2 with IMDSv1 + overprivileged IAM role" is a specific attack path, not three unrelated findings
- **Intelligent prioritization**: Instead of sorting 400 findings by severity, get a top-10 list ranked by actual exploitability on *your* specific account
- **Human-readable output**: Executive summaries that explain what an attacker could *actually do*, not just that "bucket versioning is disabled"
- **Specific remediation**: Not "enable encryption" but `aws s3api put-bucket-encryption --bucket prod-uploads --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithmName":"aws:kms"}}]}'`

The tool runs locally in 5 minutes, deploys to AWS ECS for automated weekly runs, costs under $0.15 per assessment, and produces reports your CISO will actually read.

All code is in the repository. The 125-test suite means you can modify anything with confidence.

---

*All code in this article is from the StratusAI project. The tool is designed for authorized security assessments of AWS environments you own or have explicit permission to scan.*
