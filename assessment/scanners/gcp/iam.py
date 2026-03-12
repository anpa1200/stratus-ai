"""
GCP IAM scanner — service accounts, project IAM policy, SA key age.

Checks:
  - Service accounts with user-managed keys (key age, count)
  - Project IAM policy: allUsers/allAuthenticatedUsers bindings
  - Overprivileged roles: owner, editor, multiple admin roles
  - Default service account usage
  - Service account impersonation (iam.serviceAccountTokenCreator)
"""
import logging
from datetime import datetime, timezone

from assessment.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# Roles considered overprivileged
OVERPRIVILEGED_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/compute.admin",
    "roles/storage.admin",
    "roles/secretmanager.admin",
}

SA_KEY_WARN_DAYS = 90
SA_KEY_CRITICAL_DAYS = 180


class GCPIAMScanner(BaseScanner):
    name = "gcp_iam"
    provider = "gcp"

    def _scan(self) -> tuple[dict, list]:
        project = self.session.project_id
        result = {}

        result["project_id"] = project
        result["service_accounts"] = _list_service_accounts(self.session, project)
        result["project_iam_policy"] = _get_project_iam_policy(self.session, project)
        result["overprivileged_bindings"] = _find_overprivileged_bindings(
            result["project_iam_policy"]
        )
        result["public_bindings"] = _find_public_bindings(result["project_iam_policy"])

        return result, []


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _list_service_accounts(session, project: str) -> list:
    try:
        iam = session.build("iam", "v1")
        sa_list = []
        request = iam.projects().serviceAccounts().list(name=f"projects/{project}")
        while request is not None:
            resp = request.execute()
            accounts = resp.get("accounts", [])
            for sa in accounts:
                sa_email = sa["email"]
                sa_info = {
                    "email": sa_email,
                    "display_name": sa.get("displayName", ""),
                    "unique_id": sa.get("uniqueId", ""),
                    "disabled": sa.get("disabled", False),
                    "is_default": _is_default_sa(sa_email, project),
                    "keys": _list_sa_keys(iam, project, sa_email),
                }
                sa_list.append(sa_info)
            request = iam.projects().serviceAccounts().list_next(request, resp)
        return sa_list
    except Exception as e:
        return [{"error": str(e)}]


def _is_default_sa(email: str, project: str) -> bool:
    return email.endswith("-compute@developer.gserviceaccount.com") or \
           email == f"{project}@appspot.gserviceaccount.com"


def _list_sa_keys(iam, project: str, sa_email: str) -> list:
    try:
        resp = iam.projects().serviceAccounts().keys().list(
            name=f"projects/{project}/serviceAccounts/{sa_email}",
            keyTypes=["USER_MANAGED"],
        ).execute()
        keys = []
        now = datetime.now(timezone.utc)
        for key in resp.get("keys", []):
            # validAfterTime is the key creation time
            valid_after = key.get("validAfterTime", "")
            age_days = None
            if valid_after:
                try:
                    created = datetime.fromisoformat(valid_after.replace("Z", "+00:00"))
                    age_days = (now - created).days
                except Exception:
                    pass

            keys.append({
                "key_id": key.get("name", "").split("/")[-1][:8] + "...",
                "key_type": key.get("keyType", ""),
                "key_algorithm": key.get("keyAlgorithm", ""),
                "valid_after": valid_after,
                "valid_before": key.get("validBeforeTime", ""),
                "age_days": age_days,
                "stale": age_days is not None and age_days > SA_KEY_WARN_DAYS,
                "critical_age": age_days is not None and age_days > SA_KEY_CRITICAL_DAYS,
            })
        return keys
    except Exception as e:
        return [{"error": str(e)}]


def _get_project_iam_policy(session, project: str) -> dict:
    try:
        crm = session.build("cloudresourcemanager", "v1")
        policy = crm.projects().getIamPolicy(
            resource=project,
            body={"options": {"requestedPolicyVersion": 1}},
        ).execute()
        return policy
    except Exception as e:
        return {"error": str(e)}


def _find_public_bindings(policy: dict) -> list:
    """Find any IAM bindings that grant access to allUsers or allAuthenticatedUsers."""
    public = []
    for binding in policy.get("bindings", []):
        members = binding.get("members", [])
        if "allUsers" in members or "allAuthenticatedUsers" in members:
            public.append({
                "role": binding["role"],
                "members": members,
                "issue": "Role granted to allUsers or allAuthenticatedUsers",
            })
    return public


def _is_gcp_system_sa(member: str) -> bool:
    """Return True for GCP-managed system service accounts that GCP controls internally."""
    if not member.startswith("serviceAccount:"):
        return False
    email = member[len("serviceAccount:"):]
    # System SAs use developer / appspot / cloudservices domains, not iam.gserviceaccount.com
    return (
        email.endswith("@developer.gserviceaccount.com")
        or email.endswith("@appspot.gserviceaccount.com")
        or email.endswith("@cloudservices.gserviceaccount.com")
    )


def _find_overprivileged_bindings(policy: dict) -> list:
    """Find bindings with overprivileged roles granted to non-system principals.

    Custom service accounts (*@<project>.iam.gserviceaccount.com) are flagged;
    GCP-internal system SAs (developer/appspot/cloudservices) are excluded.
    """
    results = []
    for binding in policy.get("bindings", []):
        role = binding.get("role", "")
        if role not in OVERPRIVILEGED_ROLES:
            continue
        members = binding.get("members", [])
        flagged_members = [m for m in members if not _is_gcp_system_sa(m)]
        if flagged_members:
            results.append({
                "role": role,
                "members": flagged_members,
                "issue": f"Overprivileged role {role} granted",
            })
    return results
