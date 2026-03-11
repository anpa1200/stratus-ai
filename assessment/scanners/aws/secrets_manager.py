"""
AWS Secrets Manager scanner — rotation status, resource policies, unused secrets, access patterns.
"""
import json
import logging
from datetime import datetime, timezone
from assessment.scanners.base import BaseScanner
from assessment.config import SECRETS_ROTATION_WARN_DAYS

logger = logging.getLogger(__name__)


class SecretsManagerScanner(BaseScanner):
    name = "secrets_manager"
    provider = "aws"

    def _scan(self) -> tuple[dict, list]:
        sm = self.session.client("secretsmanager", region_name=self.region)
        result = {
            "region": self.region,
            "secrets": _scan_secrets(sm),
        }
        return result, []


def _scan_secrets(sm) -> list:
    secrets = []
    now = datetime.now(timezone.utc)
    try:
        paginator = sm.get_paginator("list_secrets")
        for page in paginator.paginate():
            for secret in page["SecretList"]:
                secret_id = secret["ARN"]
                name = secret.get("Name", "")

                info = {
                    "name": name,
                    "arn": secret_id,
                    "description": secret.get("Description", ""),
                    "rotation_enabled": secret.get("RotationEnabled", False),
                    "last_rotated": str(secret.get("LastRotatedDate", "never")),
                    "last_accessed": str(secret.get("LastAccessedDate", "never")),
                    "last_changed": str(secret.get("LastChangedDate", "")),
                    "kms_key_id": secret.get("KmsKeyId", ""),
                    "uses_default_kms": not bool(secret.get("KmsKeyId")),
                    "tags": {t["Key"]: t["Value"] for t in secret.get("Tags", [])},
                }

                # Check days since last rotation
                last_rotated = secret.get("LastRotatedDate") or secret.get("LastChangedDate")
                if last_rotated:
                    try:
                        if hasattr(last_rotated, "tzinfo"):
                            if last_rotated.tzinfo is None:
                                last_rotated = last_rotated.replace(tzinfo=timezone.utc)
                        days_since = (now - last_rotated).days
                        info["days_since_rotation"] = days_since
                        info["rotation_overdue"] = days_since > SECRETS_ROTATION_WARN_DAYS
                    except Exception:
                        info["days_since_rotation"] = "unknown"
                else:
                    info["days_since_rotation"] = "never rotated"
                    info["rotation_overdue"] = True

                # Check for resource-based policy (cross-account access)
                try:
                    pol_resp = sm.get_resource_policy(SecretId=secret_id)
                    policy_str = pol_resp.get("ResourcePolicy", "")
                    if policy_str:
                        policy_doc = json.loads(policy_str)
                        info["resource_policy"] = _analyze_secret_policy(policy_doc)
                    else:
                        info["resource_policy"] = {"exists": False}
                except sm.exceptions.ResourceNotFoundException:
                    info["resource_policy"] = {"exists": False}
                except Exception as e:
                    info["resource_policy"] = {"error": str(e)}

                secrets.append(info)
    except Exception as e:
        return [{"error": str(e)}]
    return secrets


def _analyze_secret_policy(policy_doc: dict) -> dict:
    """Check secret resource policy for overly permissive statements."""
    issues = []
    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", "")
        if principal == "*":
            if not stmt.get("Condition"):
                issues.append("Principal * — secret publicly accessible")
        elif isinstance(principal, dict):
            aws = principal.get("AWS", "")
            if isinstance(aws, list):
                if any(a == "*" for a in aws):
                    issues.append("AWS Principal * in list — any account can access secret")
            elif aws == "*":
                issues.append("AWS Principal * — any AWS account can access secret")
    return {
        "exists": True,
        "statement_count": len(policy_doc.get("Statement", [])),
        "issues": issues,
    }
