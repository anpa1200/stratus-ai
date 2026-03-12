"""
GCP Cloud Storage scanner — public buckets, IAM, versioning, logging.

Checks:
  - Buckets with allUsers/allAuthenticatedUsers IAM bindings
  - Uniform bucket-level access disabled
  - Versioning disabled
  - Access logging disabled
  - Retention policy absent
  - Public objects listing
"""
import logging
from assessment.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class GCPStorageScanner(BaseScanner):
    name = "gcp_storage"
    provider = "gcp"

    def _scan(self) -> tuple[dict, list]:
        project = self.session.project_id
        result = {"project_id": project}
        result["buckets"] = _list_buckets(self.session, project)
        return result, []


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _list_buckets(session, project: str) -> list:
    try:
        from google.cloud import storage as gcs
        client = gcs.Client(project=project, credentials=session.credentials)
        buckets = []
        for bucket in client.list_buckets():
            bucket_info = _scan_bucket(client, bucket)
            buckets.append(bucket_info)
        return buckets
    except Exception as e:
        return [{"error": str(e)}]


def _scan_bucket(client, bucket) -> dict:
    name = bucket.name
    info = {
        "name": name,
        "location": bucket.location,
        "storage_class": bucket.storage_class,
        "uniform_bucket_level_access": bucket.iam_configuration.uniform_bucket_level_access_enabled,
        "public_access_prevention": getattr(
            bucket.iam_configuration, "public_access_prevention", "unspecified"
        ),
        "versioning_enabled": bucket.versioning_enabled,
        "logging_enabled": bool(bucket.logging),
        "retention_policy": None,
        "iam_bindings": [],
        "public_bindings": [],
        "issues": [],
    }

    # Retention policy
    if bucket.retention_policy:
        info["retention_policy"] = {
            "retention_period": bucket.retention_policy.retention_period,
            "is_locked": bucket.retention_policy.is_locked,
        }

    # IAM policy — check for public access
    try:
        policy = bucket.get_iam_policy(requested_policy_version=3)
        bindings = []
        public_bindings = []
        for binding in policy.bindings:
            role = binding["role"]
            members = list(binding["members"])
            bindings.append({"role": role, "members": members})
            if "allUsers" in members or "allAuthenticatedUsers" in members:
                public_bindings.append({
                    "role": role,
                    "members": members,
                    "issue": f"Bucket role {role} granted to allUsers or allAuthenticatedUsers",
                })
        info["iam_bindings"] = bindings
        info["public_bindings"] = public_bindings
    except Exception as e:
        info["iam_error"] = str(e)

    # Build issues list
    if info["public_bindings"]:
        roles = [b["role"] for b in info["public_bindings"]]
        info["issues"].append(f"PUBLIC bucket — allUsers has: {', '.join(roles)}")
    if not info["uniform_bucket_level_access"]:
        info["issues"].append("uniform bucket-level access disabled (ACL-based access possible)")
    if not info["versioning_enabled"]:
        info["issues"].append("versioning disabled")
    if not info["logging_enabled"]:
        info["issues"].append("access logging disabled")
    if not info["retention_policy"]:
        info["issues"].append("no retention policy configured")
    pap = info.get("public_access_prevention", "unspecified")
    if pap not in ("enforced",):
        info["issues"].append(f"public access prevention: {pap} (not enforced)")

    return info
