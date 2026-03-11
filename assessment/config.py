"""
Configuration constants for cloud security assessment.
"""
import os

# ─── AWS Defaults ─────────────────────────────────────────────────────────────

DEFAULT_AWS_REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]

# Ports considered sensitive — security groups allowing 0.0.0.0/0 inbound flagged
SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    2375: "Docker API (unencrypted)",
    2376: "Docker API",
    4243: "Docker API",
    11211: "Memcached",
    5601: "Kibana",
    8500: "Consul",
    2181: "Zookeeper",
    9092: "Kafka",
}

# IAM managed policies that should trigger HIGH finding if attached to users directly
OVERPRIVILEGED_MANAGED_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
}

# IAM inline policy actions that are always concerning
DANGEROUS_IAM_ACTIONS = {
    "iam:*",
    "iam:PassRole",
    "sts:AssumeRole",
    "ec2:*",
    "s3:*",
    "lambda:*",
    "*:*",
}

# Access key age thresholds (days)
ACCESS_KEY_WARN_DAYS = 90
ACCESS_KEY_CRITICAL_DAYS = 180

# ─── External scan defaults ───────────────────────────────────────────────────

# Ports to scan in external mode
EXTERNAL_SCAN_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,27017"

# TLS minimum acceptable version
MIN_TLS_VERSION = "TLSv1.2"

# HTTP security headers that should be present
EXPECTED_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-XSS-Protection",
    "Permissions-Policy",
    "Referrer-Policy",
]

# ─── AI settings ──────────────────────────────────────────────────────────────

DEFAULT_MODEL = "claude-sonnet-4-6"
MAX_SCAN_OUTPUT_CHARS = 40_000
INTER_REQUEST_DELAY = 3          # seconds between sequential AI calls

# ─── Claude model pricing (USD per million tokens) ────────────────────────────
# Prices as of 2025. Update when pricing changes.

MODEL_PRICING = {
    "claude-opus-4-6":            {"input": 15.00, "output": 75.00},
    "claude-sonnet-4-6":          {"input": 3.00,  "output": 15.00},
    "claude-haiku-4-5-20251001":  {"input": 0.25,  "output": 1.25},
    # Legacy names
    "claude-3-5-sonnet-20241022": {"input": 3.00,  "output": 15.00},
    "claude-3-haiku-20240307":    {"input": 0.25,  "output": 1.25},
}

# ─── Lambda security ─────────────────────────────────────────────────────────

# Lambda runtimes considered EOL / deprecated
DEPRECATED_LAMBDA_RUNTIMES = {
    "python2.7", "python3.6", "python3.7",
    "nodejs10.x", "nodejs12.x", "nodejs14.x",
    "ruby2.5", "ruby2.7",
    "java8", "dotnetcore2.1", "dotnetcore3.1",
    "go1.x",
}

# ─── Secrets Manager ─────────────────────────────────────────────────────────

# Secrets not rotated in this many days are flagged
SECRETS_ROTATION_WARN_DAYS = 90

# ─── KMS ─────────────────────────────────────────────────────────────────────

# KMS keys not rotated (annual rotation disabled) are flagged
KMS_ROTATION_REQUIRED = True
