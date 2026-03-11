"""
AWS S3 scanner — public buckets, encryption, versioning, logging, replication.
"""
import logging
from assessment.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class S3Scanner(BaseScanner):
    name = "s3"
    provider = "aws"

    def _scan(self) -> tuple[dict, list]:
        s3 = self.session.client("s3")
        result = {}
        result["buckets"] = _scan_all_buckets(s3)
        result["account_public_access_block"] = _get_account_public_access_block(s3)
        return result, []


def _scan_all_buckets(s3) -> list:
    buckets = []
    try:
        resp = s3.list_buckets()
        for b in resp.get("Buckets", []):
            name = b["Name"]
            info = {
                "name": name,
                "created": str(b.get("CreationDate", "")),
            }

            # Bucket location
            try:
                loc = s3.get_bucket_location(Bucket=name)
                info["region"] = loc.get("LocationConstraint") or "us-east-1"
            except Exception:
                info["region"] = "unknown"

            # Public access block settings
            try:
                pab = s3.get_public_access_block(Bucket=name)
                cfg = pab["PublicAccessBlockConfiguration"]
                info["public_access_block"] = {
                    "block_public_acls": cfg.get("BlockPublicAcls", False),
                    "ignore_public_acls": cfg.get("IgnorePublicAcls", False),
                    "block_public_policy": cfg.get("BlockPublicPolicy", False),
                    "restrict_public_buckets": cfg.get("RestrictPublicBuckets", False),
                }
                info["all_public_access_blocked"] = all(cfg.get(k, False) for k in [
                    "BlockPublicAcls", "IgnorePublicAcls",
                    "BlockPublicPolicy", "RestrictPublicBuckets"
                ])
            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                info["public_access_block"] = "not configured"
                info["all_public_access_blocked"] = False
            except Exception as e:
                info["public_access_block"] = f"error: {e}"
                info["all_public_access_blocked"] = False

            # ACL
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                info["acl_public_read"] = False
                info["acl_public_write"] = False
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    uri = grantee.get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        perm = grant.get("Permission", "")
                        if "READ" in perm:
                            info["acl_public_read"] = True
                        if "WRITE" in perm or "FULL_CONTROL" in perm:
                            info["acl_public_write"] = True
            except Exception as e:
                info["acl"] = f"error: {e}"

            # Bucket policy — check for public statements
            try:
                policy = s3.get_bucket_policy(Bucket=name)
                import json
                doc = json.loads(policy["Policy"])
                info["has_bucket_policy"] = True
                info["policy_allows_public"] = _policy_allows_public(doc)
                info["bucket_policy_summary"] = _summarise_policy(doc)
            except s3.exceptions.NoSuchBucketPolicy:
                info["has_bucket_policy"] = False
                info["policy_allows_public"] = False
            except Exception as e:
                info["bucket_policy"] = f"error: {e}"

            # Encryption
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
                info["encryption"] = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] if rules else "none"
            except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                info["encryption"] = "none"
            except Exception:
                info["encryption"] = "unknown"

            # Versioning
            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                info["versioning"] = ver.get("Status", "Disabled")
                info["mfa_delete"] = ver.get("MFADelete", "Disabled")
            except Exception:
                info["versioning"] = "unknown"

            # Logging
            try:
                log = s3.get_bucket_logging(Bucket=name)
                info["logging_enabled"] = "LoggingEnabled" in log
                if info["logging_enabled"]:
                    info["log_destination"] = log["LoggingEnabled"].get("TargetBucket", "")
            except Exception:
                info["logging_enabled"] = "unknown"

            buckets.append(info)

    except Exception as e:
        return [{"error": str(e)}]

    return buckets


def _get_account_public_access_block(s3) -> dict:
    try:
        sts = s3._endpoint.host  # just to get account id elsewhere
        # Use S3Control for account-level setting
        import boto3
        sts_client = boto3.client("sts")
        account_id = sts_client.get_caller_identity()["Account"]
        s3control = boto3.client("s3control", region_name="us-east-1")
        resp = s3control.get_public_access_block(AccountId=account_id)
        cfg = resp["PublicAccessBlockConfiguration"]
        return {
            "account_id": account_id,
            "block_public_acls": cfg.get("BlockPublicAcls", False),
            "ignore_public_acls": cfg.get("IgnorePublicAcls", False),
            "block_public_policy": cfg.get("BlockPublicPolicy", False),
            "restrict_public_buckets": cfg.get("RestrictPublicBuckets", False),
        }
    except Exception as e:
        return {"error": str(e), "note": "Account-level S3 public access block status unknown"}


def _policy_allows_public(doc: dict) -> bool:
    """Return True if bucket policy has Statement allowing Principal: * without conditions."""
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", "")
        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
            # Only flag if no condition restricts it
            if not stmt.get("Condition"):
                return True
    return False


def _summarise_policy(doc: dict) -> list:
    """Return concise summary of each policy statement."""
    summary = []
    for stmt in doc.get("Statement", []):
        summary.append({
            "effect": stmt.get("Effect"),
            "principal": stmt.get("Principal"),
            "action": stmt.get("Action"),
            "condition": bool(stmt.get("Condition")),
        })
    return summary
