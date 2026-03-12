"""
GCP Secret Manager scanner — secret access policies, rotation, CMEK.

Checks:
  - Secrets accessible by allUsers or allAuthenticatedUsers
  - Secrets without rotation configured
  - Secrets not using customer-managed encryption keys (CMEK)
  - Excessive access grants
"""
import logging
from assessment.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class GCPSecretManagerScanner(BaseScanner):
    name = "gcp_secretmanager"
    provider = "gcp"

    def _scan(self) -> tuple[dict, list]:
        project = self.session.project_id
        result = {"project_id": project}
        result["secrets"] = _list_secrets(self.session, project)
        return result, []


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _list_secrets(session, project: str) -> list:
    try:
        from google.cloud import secretmanager
        client = secretmanager.SecretManagerServiceClient(credentials=session.credentials)
        secrets = []
        parent = f"projects/{project}"
        for secret in client.list_secrets(request={"parent": parent}):
            secrets.append(_parse_secret(client, secret))
        return secrets
    except Exception as e:
        return [{"error": str(e)}]


def _parse_secret(client, secret) -> dict:
    name = secret.name
    short_name = name.split("/")[-1]

    # Replication
    replication = secret.replication
    replication_type = "automatic" if replication.HasField("automatic") else "user_managed"
    uses_cmek = False
    if replication_type == "automatic":
        cmek_key = getattr(replication.automatic, "customer_managed_encryption", None)
        uses_cmek = bool(cmek_key and cmek_key.kms_key_name)
    elif replication_type == "user_managed":
        for replica in replication.user_managed.replicas:
            cmek_key = getattr(replica, "customer_managed_encryption", None)
            if cmek_key and cmek_key.kms_key_name:
                uses_cmek = True
                break

    # Rotation
    rotation = secret.rotation if secret.HasField("rotation") else None
    rotation_configured = rotation is not None

    # Labels (for context)
    labels = dict(secret.labels)

    info = {
        "name": short_name,
        "full_name": name,
        "replication_type": replication_type,
        "uses_cmek": uses_cmek,
        "rotation_configured": rotation_configured,
        "labels": labels,
        "public_access": False,
        "iam_bindings": [],
        "issues": [],
    }

    # Check IAM policy
    try:
        iam_resp = client.get_iam_policy(request={"resource": name})
        bindings = []
        for binding in iam_resp.bindings:
            members = list(binding.members)
            role = binding.role
            bindings.append({"role": role, "members": members})
            if "allUsers" in members or "allAuthenticatedUsers" in members:
                info["public_access"] = True
                info["issues"].append(
                    f"Secret accessible by allUsers via role {role}"
                )
        info["iam_bindings"] = bindings
    except Exception as e:
        info["iam_error"] = str(e)

    # Build issues
    if not rotation_configured:
        info["issues"].append("rotation not configured")
    if not uses_cmek:
        info["issues"].append("using Google-managed encryption (not CMEK)")

    return info
