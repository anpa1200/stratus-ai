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

EXTERNAL_SCAN_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,27017"
MIN_TLS_VERSION = "TLSv1.2"
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
INTER_REQUEST_DELAY = 1          # seconds between sequential AI calls (reduced from 3)

# Modules where a cheaper/faster model produces equivalent results.
# The analyzer auto-downgrades these to the cheaper model in the same provider family.
SIMPLE_MODULES = {
    # External
    "ports", "ssl", "http_headers", "dns",
    # AWS
    "kms", "secrets_manager",
    # GCP
    "gcp_secretmanager", "gcp_logging",
}

# Per-module output token budgets — avoids oversized reserved buffers
MODULE_MAX_OUTPUT_TOKENS = {
    # Simple external modules
    "ports": 1024,
    "ssl": 1024,
    "http_headers": 1024,
    "dns": 512,
    # Simple cloud modules
    "kms": 1500,
    "secrets_manager": 1500,
    "gcp_secretmanager": 1500,
    "gcp_logging": 1500,
    # Standard modules
    "_default_module": 4096,
    # Synthesis always gets the full budget
    "_synthesis": 8192,
}

# ─── Multi-provider model pricing (USD per million tokens) ────────────────────

MODEL_PRICING = {
    # ── Anthropic ──────────────────────────────────────────────────────────────
    "claude-opus-4-6":              {"input": 15.00,  "output": 75.00},
    "claude-sonnet-4-6":            {"input": 3.00,   "output": 15.00},
    "claude-haiku-4-5-20251001":    {"input": 0.25,   "output": 1.25},
    # Legacy
    "claude-3-5-sonnet-20241022":   {"input": 3.00,   "output": 15.00},
    "claude-3-haiku-20240307":      {"input": 0.25,   "output": 1.25},

    # ── OpenAI ─────────────────────────────────────────────────────────────────
    "gpt-4o":                       {"input": 2.50,   "output": 10.00},
    "gpt-4o-mini":                  {"input": 0.15,   "output": 0.60},
    "gpt-4-turbo":                  {"input": 10.00,  "output": 30.00},
    "o1":                           {"input": 15.00,  "output": 60.00},
    "o1-mini":                      {"input": 3.00,   "output": 12.00},
    "o3":                           {"input": 10.00,  "output": 40.00},
    "o3-mini":                      {"input": 1.10,   "output": 4.40},
    "o4-mini":                      {"input": 1.10,   "output": 4.40},

    # ── Google Gemini ──────────────────────────────────────────────────────────
    "gemini-2.0-flash":             {"input": 0.10,   "output": 0.40},
    "gemini-2.0-flash-thinking":    {"input": 0.15,   "output": 0.60},
    "gemini-1.5-pro":               {"input": 1.25,   "output": 5.00},
    "gemini-1.5-flash":             {"input": 0.075,  "output": 0.30},
    "gemini-1.5-flash-8b":          {"input": 0.0375, "output": 0.15},
}

# Friendly display names for the summary box
MODEL_DISPLAY_NAMES = {
    "claude-sonnet-4-6":          "Claude Sonnet 4.6",
    "claude-opus-4-6":            "Claude Opus 4.6",
    "claude-haiku-4-5-20251001":  "Claude Haiku 4.5",
    "gpt-4o":                     "GPT-4o",
    "gpt-4o-mini":                "GPT-4o mini",
    "o1":                         "o1",
    "o3":                         "o3",
    "o3-mini":                    "o3-mini",
    "o4-mini":                    "o4-mini",
    "gemini-2.0-flash":           "Gemini 2.0 Flash",
    "gemini-1.5-pro":             "Gemini 1.5 Pro",
    "gemini-1.5-flash":           "Gemini 1.5 Flash",
}

# ─── Lambda security ─────────────────────────────────────────────────────────

DEPRECATED_LAMBDA_RUNTIMES = {
    "python2.7", "python3.6", "python3.7",
    "nodejs10.x", "nodejs12.x", "nodejs14.x",
    "ruby2.5", "ruby2.7",
    "java8", "dotnetcore2.1", "dotnetcore3.1",
    "go1.x",
}

# ─── Secrets Manager ─────────────────────────────────────────────────────────

SECRETS_ROTATION_WARN_DAYS = 90

# ─── KMS ─────────────────────────────────────────────────────────────────────

KMS_ROTATION_REQUIRED = True
