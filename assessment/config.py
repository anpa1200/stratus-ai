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
}

# IAM managed policies that should trigger HIGH finding if attached to users directly
OVERPRIVILEGED_MANAGED_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
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
]

# ─── AI settings ──────────────────────────────────────────────────────────────

DEFAULT_MODEL = "claude-sonnet-4-6"
MAX_SCAN_OUTPUT_CHARS = 40_000
INTER_REQUEST_DELAY = 3          # seconds between sequential AI calls
