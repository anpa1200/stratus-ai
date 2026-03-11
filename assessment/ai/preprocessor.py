"""
Pre-process raw scanner output before sending to the AI.
Reduces prompt size 60-90% while preserving all high-signal security data.
"""
import logging

logger = logging.getLogger(__name__)


def preprocess(module_name: str, raw: dict) -> dict:
    """Return a filtered/compressed copy of raw scanner output."""
    handler = _HANDLERS.get(module_name)
    if handler:
        try:
            return handler(raw)
        except Exception as e:
            logger.warning(f"Preprocessor failed for {module_name}: {e}")
    return raw


# ─── Per-module handlers ──────────────────────────────────────────────────────

def _process_iam(raw: dict) -> dict:
    out = {}
    out["account_summary"] = raw.get("account_summary", {})
    out["password_policy"] = raw.get("password_policy", {})
    out["root_account"] = raw.get("root_account", {})

    users = raw.get("users", [])
    flagged_users = []
    for u in users:
        issues = []
        if not u.get("mfa_enabled"):
            issues.append("no MFA")
        for key in u.get("access_keys", []):
            if key.get("critical_age"):
                issues.append(f"access key {key['key_id']} is {key['age_days']}d old (CRITICAL)")
            elif key.get("stale"):
                issues.append(f"access key {key['key_id']} is {key['age_days']}d old (stale)")
        for pol in u.get("attached_policies", []):
            from assessment.config import OVERPRIVILEGED_MANAGED_POLICIES
            if pol in OVERPRIVILEGED_MANAGED_POLICIES:
                issues.append(f"admin policy: {pol.split('/')[-1]}")

        if issues or u.get("inline_policies"):
            u["_issues"] = issues
            flagged_users.append(u)

    out["flagged_users"] = flagged_users
    out["total_users"] = len(users)
    out["roles_with_star_policies"] = raw.get("roles_with_star_policies", [])
    out["attached_admin_policies"] = raw.get("attached_admin_policies", [])
    return out


def _process_s3(raw: dict) -> dict:
    out = {}
    out["account_public_access_block"] = raw.get("account_public_access_block", {})

    buckets = raw.get("buckets", [])
    out["total_buckets"] = len(buckets)

    flagged = []
    for b in buckets:
        issues = []
        if b.get("acl_public_read"):
            issues.append("public ACL read")
        if b.get("acl_public_write"):
            issues.append("public ACL write")
        if b.get("policy_allows_public"):
            issues.append("bucket policy allows public access")
        if not b.get("all_public_access_blocked"):
            issues.append("public access block not fully configured")
        if b.get("encryption") == "none":
            issues.append("no encryption")
        if b.get("versioning") in ("Disabled", "Suspended", None):
            issues.append(f"versioning {b.get('versioning', 'disabled')}")
        if not b.get("logging_enabled"):
            issues.append("logging disabled")

        if issues:
            b["_issues"] = issues
            b.pop("bucket_policy_summary", None)
            flagged.append(b)

    out["flagged_buckets"] = flagged
    out["clean_bucket_count"] = len(buckets) - len(flagged)
    return out


def _process_ec2(raw: dict) -> dict:
    out = {"region": raw.get("region", "")}

    sgs = raw.get("security_groups", [])
    risky_sgs = [sg for sg in sgs if sg.get("inbound_open_to_world") or sg.get("inbound_sensitive_ports_open")]
    out["risky_security_groups"] = risky_sgs
    out["total_security_groups"] = len(sgs)

    instances = raw.get("instances", [])
    flagged_instances = []
    for inst in instances:
        issues = list(inst.get("issues", []))
        if not inst.get("imdsv2_required"):
            issues.append("IMDSv2 not required (vulnerable to SSRF-based credential theft)")
        if inst.get("unencrypted_volumes"):
            issues.append(f"unencrypted volumes: {inst['unencrypted_volumes']}")
        if issues:
            inst["_issues"] = issues
            flagged_instances.append(inst)

    out["flagged_instances"] = flagged_instances
    out["total_instances"] = len(instances)
    out["public_snapshots"] = raw.get("public_snapshots", [])
    out["ebs_encryption_default"] = raw.get("ebs_encryption_default", {})
    out["vpc_summary"] = [
        v for v in raw.get("vpc_summary", [])
        if v.get("is_default") or not v.get("flow_logs_enabled")
    ]
    return out


def _process_cloudtrail(raw: dict) -> dict:
    out = {}
    ct = raw.get("cloudtrail", {})
    out["cloudtrail"] = {
        "trail_count": ct.get("trail_count", 0),
        "trails": ct.get("trails", []),
        "note": ct.get("note", ""),
    }
    out["guardduty"] = raw.get("guardduty", {})
    out["security_hub"] = raw.get("security_hub", {})
    out["aws_config"] = raw.get("aws_config", {})
    out["access_analyzer"] = raw.get("access_analyzer", {})
    return out


def _process_rds(raw: dict) -> dict:
    out = {"region": raw.get("region", "")}
    instances = raw.get("instances", [])
    out["flagged_instances"] = [i for i in instances if i.get("issues")]
    out["total_instances"] = len(instances)
    out["public_snapshots"] = raw.get("snapshots_public", [])
    out["parameter_group_issues"] = raw.get("parameter_groups", [])
    return out


def _process_lambda(raw: dict) -> dict:
    out = {"region": raw.get("region", "")}
    functions = raw.get("functions", [])
    out["total_functions"] = len(functions)

    flagged = []
    for fn in functions:
        issues = []
        if fn.get("deprecated_runtime"):
            issues.append(f"deprecated runtime: {fn.get('runtime')}")
        if fn.get("function_url") and fn["function_url"].get("public"):
            issues.append(f"public function URL (no auth): {fn['function_url'].get('url', '')}")
        policy = fn.get("resource_policy", {})
        if policy.get("issues"):
            issues.extend(policy["issues"])
        if fn.get("has_suspicious_env_vars"):
            issues.append(f"suspicious env vars (potential secrets): {fn.get('suspicious_env_vars', [])}")
        if fn.get("env_var_count", 0) > 0 and not fn.get("env_encrypted"):
            issues.append("environment variables not encrypted with customer KMS key")

        if issues:
            fn["_issues"] = issues
            flagged.append(fn)

    out["flagged_functions"] = flagged
    out["clean_function_count"] = len(functions) - len(flagged)
    return out


def _process_kms(raw: dict) -> dict:
    out = {"region": raw.get("region", "")}
    keys = raw.get("keys", [])
    out["total_customer_managed_keys"] = len(keys)

    flagged = []
    for key in keys:
        issues = []
        if key.get("rotation_enabled") is False:
            issues.append("automatic key rotation disabled")
        policy = key.get("policy_analysis", {})
        if policy.get("issues"):
            issues.extend(policy["issues"])
        if key.get("deletion_pending"):
            issues.append(f"key pending deletion on {key.get('deletion_date')}")
        if not key.get("enabled") and not key.get("deletion_pending"):
            issues.append(f"key in state: {key.get('key_state')}")

        if issues:
            key["_issues"] = issues
            flagged.append(key)

    out["flagged_keys"] = flagged
    out["clean_key_count"] = len(keys) - len(flagged)
    return out


def _process_secrets_manager(raw: dict) -> dict:
    out = {"region": raw.get("region", "")}
    secrets = raw.get("secrets", [])
    out["total_secrets"] = len(secrets)

    flagged = []
    for s in secrets:
        issues = []
        if not s.get("rotation_enabled"):
            issues.append("rotation not enabled")
        if s.get("rotation_overdue"):
            days = s.get("days_since_rotation", "unknown")
            issues.append(f"rotation overdue ({days} days since last rotation)")
        if s.get("uses_default_kms"):
            issues.append("using default KMS key (not customer-managed)")
        policy = s.get("resource_policy", {})
        if policy.get("issues"):
            issues.extend(policy["issues"])

        if issues:
            s["_issues"] = issues
            s.pop("tags", None)
            flagged.append(s)

    out["flagged_secrets"] = flagged
    out["clean_secret_count"] = len(secrets) - len(flagged)
    return out


def _process_eks(raw: dict) -> dict:
    out = {"region": raw.get("region", "")}
    clusters = raw.get("clusters", [])
    out["total_clusters"] = len(clusters)

    flagged = []
    for cluster in clusters:
        issues = []
        if cluster.get("endpoint_open_to_world"):
            cidrs = cluster.get("public_access_cidrs", [])
            issues.append(f"API endpoint public and open to {cidrs}")
        if cluster.get("deprecated_version"):
            issues.append(f"deprecated Kubernetes version: {cluster.get('kubernetes_version')}")
        logging_info = cluster.get("logging", {})
        if not logging_info.get("audit_logging"):
            issues.append("audit logging disabled")
        if not logging_info.get("api_logging"):
            issues.append("API server logging disabled")
        secrets_enc = cluster.get("secrets_encryption", {})
        if not secrets_enc.get("enabled"):
            issues.append("Kubernetes secrets not encrypted with KMS")

        if issues:
            cluster["_issues"] = issues
            flagged.append(cluster)

    out["flagged_clusters"] = flagged
    out["clean_cluster_count"] = len(clusters) - len(flagged)
    return out


def _process_ports(raw: dict) -> dict:
    out = {"target": raw.get("target", "")}
    nmap = raw.get("nmap_result", {})
    out["open_ports"] = nmap.get("open_ports", [])
    if nmap.get("error"):
        out["nmap_error"] = nmap["error"]
    return out


def _process_ssl(raw: dict) -> dict:
    out = {"target": raw.get("target", "")}
    for key in ("https_443", "https_8443"):
        tls = raw.get(key, {})
        if tls:
            summary = {k: v for k, v in tls.items() if k not in ("raw_output",)}
            out[key] = summary
    if raw.get("sslscan"):
        out["sslscan"] = raw["sslscan"]
    return out


def _process_http_headers(raw: dict) -> dict:
    out = {"target": raw.get("target", "")}
    https = raw.get("https", {})
    if https:
        out["https"] = {
            "status_code": https.get("status_code"),
            "server": https.get("server"),
            "x_powered_by": https.get("x_powered_by"),
            "missing_security_headers": https.get("missing_security_headers", []),
            "hsts_max_age": https.get("hsts_max_age"),
            "hsts_include_subdomains": https.get("hsts_include_subdomains"),
            "version_disclosure": https.get("version_disclosure", []),
            "cookies": https.get("cookies", []),
            "error": https.get("error"),
        }
    out["http"] = raw.get("http", {})
    return out


def _process_dns(raw: dict) -> dict:
    return raw


# ─── Handler registry ─────────────────────────────────────────────────────────

_HANDLERS = {
    "iam": _process_iam,
    "s3": _process_s3,
    "ec2": _process_ec2,
    "cloudtrail": _process_cloudtrail,
    "rds": _process_rds,
    "lambda": _process_lambda,
    "kms": _process_kms,
    "secrets_manager": _process_secrets_manager,
    "eks": _process_eks,
    "ports": _process_ports,
    "ssl": _process_ssl,
    "http_headers": _process_http_headers,
    "dns": _process_dns,
}
