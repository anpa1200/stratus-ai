"""
AWS KMS scanner — key rotation, key policies, grants, disabled keys.
"""
import json
import logging
from assessment.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class KMSScanner(BaseScanner):
    name = "kms"
    provider = "aws"

    def _scan(self) -> tuple[dict, list]:
        kms = self.session.client("kms", region_name=self.region)
        result = {
            "region": self.region,
            "keys": _scan_kms_keys(kms),
        }
        return result, []


def _scan_kms_keys(kms) -> list:
    keys = []
    try:
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key_ref in page["Keys"]:
                key_id = key_ref["KeyId"]
                try:
                    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                except Exception:
                    continue

                # Only check customer-managed keys (not AWS-managed or AWS-owned)
                key_manager = meta.get("KeyManager", "")
                if key_manager != "CUSTOMER":
                    continue

                key_state = meta.get("KeyState", "")
                info = {
                    "key_id": key_id,
                    "arn": meta.get("Arn", ""),
                    "description": meta.get("Description", ""),
                    "key_state": key_state,
                    "enabled": key_state == "Enabled",
                    "key_usage": meta.get("KeyUsage", ""),
                    "key_spec": meta.get("KeySpec", ""),
                    "multi_region": meta.get("MultiRegion", False),
                    "deletion_pending": key_state == "PendingDeletion",
                    "deletion_date": str(meta.get("DeletionDate", "")),
                }

                # Check automatic key rotation (only for symmetric keys)
                if meta.get("KeyUsage") == "ENCRYPT_DECRYPT" and meta.get("KeySpec") == "SYMMETRIC_DEFAULT":
                    try:
                        rot = kms.get_key_rotation_status(KeyId=key_id)
                        info["rotation_enabled"] = rot.get("KeyRotationEnabled", False)
                    except Exception:
                        info["rotation_enabled"] = "unknown"
                else:
                    info["rotation_enabled"] = "N/A (asymmetric key)"

                # Check key policy for public/cross-account access
                try:
                    pol_resp = kms.get_key_policy(KeyId=key_id, PolicyName="default")
                    policy_doc = json.loads(pol_resp["Policy"])
                    info["policy_analysis"] = _analyze_kms_policy(policy_doc)
                except Exception as e:
                    info["policy_analysis"] = {"error": str(e)}

                # Count grants
                try:
                    grants = kms.list_grants(KeyId=key_id)
                    info["grant_count"] = len(grants.get("Grants", []))
                except Exception:
                    info["grant_count"] = "unknown"

                keys.append(info)
    except Exception as e:
        return [{"error": str(e)}]
    return keys


def _analyze_kms_policy(policy_doc: dict) -> dict:
    """Check KMS key policy for overly permissive statements."""
    issues = []
    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", "")
        if principal == "*":
            if not stmt.get("Condition"):
                issues.append("Principal * with no condition — key is publicly accessible")
        elif isinstance(principal, dict):
            aws = principal.get("AWS", "")
            if aws == "*":
                issues.append("AWS Principal * — any AWS account/role can use this key")
    return {
        "statement_count": len(policy_doc.get("Statement", [])),
        "issues": issues,
    }
