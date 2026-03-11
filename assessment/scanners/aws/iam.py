"""
AWS IAM scanner — checks users, roles, policies, MFA, access keys, password policy.
"""
import logging
from datetime import datetime, timezone
from assessment.scanners.base import BaseScanner
from assessment.config import (
    OVERPRIVILEGED_MANAGED_POLICIES,
    ACCESS_KEY_WARN_DAYS,
    ACCESS_KEY_CRITICAL_DAYS,
)

logger = logging.getLogger(__name__)


class IAMScanner(BaseScanner):
    name = "iam"
    provider = "aws"

    def _scan(self) -> tuple[dict, list]:
        iam = self.session.client("iam")
        result = {}

        result["account_summary"] = _get_account_summary(iam)
        result["password_policy"] = _get_password_policy(iam)
        result["root_account"] = _check_root_account(iam)
        result["users"] = _get_users_with_details(iam)
        result["roles_with_star_policies"] = _get_overprivileged_roles(iam)
        result["groups"] = _get_groups_summary(iam)
        result["attached_admin_policies"] = _find_admin_policy_attachments(iam)

        return result, []


def _get_account_summary(iam) -> dict:
    try:
        resp = iam.get_account_summary()
        summary = resp.get("SummaryMap", {})
        return {
            "users": summary.get("Users", 0),
            "groups": summary.get("Groups", 0),
            "roles": summary.get("Roles", 0),
            "policies": summary.get("Policies", 0),
            "mfa_devices": summary.get("MFADevices", 0),
            "mfa_devices_in_use": summary.get("MFADevicesInUse", 0),
            "account_signing_certificates": summary.get("AccountSigningCertificatesPresent", 0),
            "account_access_keys_present": summary.get("AccountAccessKeysPresent", 0),
            "account_mfa_enabled": summary.get("AccountMFAEnabled", 0),
        }
    except Exception as e:
        return {"error": str(e)}


def _get_password_policy(iam) -> dict:
    try:
        resp = iam.get_account_password_policy()
        p = resp["PasswordPolicy"]
        return {
            "minimum_password_length": p.get("MinimumPasswordLength", 0),
            "require_uppercase": p.get("RequireUppercaseCharacters", False),
            "require_lowercase": p.get("RequireLowercaseCharacters", False),
            "require_numbers": p.get("RequireNumbers", False),
            "require_symbols": p.get("RequireSymbols", False),
            "allow_users_to_change": p.get("AllowUsersToChangePassword", False),
            "expire_passwords": p.get("ExpirePasswords", False),
            "max_password_age": p.get("MaxPasswordAge"),
            "password_reuse_prevention": p.get("PasswordReusePrevention"),
            "hard_expiry": p.get("HardExpiry", False),
        }
    except iam.exceptions.NoSuchEntityException:
        return {"configured": False, "note": "No password policy set — AWS defaults apply (no expiry, no complexity)"}
    except Exception as e:
        return {"error": str(e)}


def _check_root_account(iam) -> dict:
    """Check root account security posture via credential report."""
    try:
        import time
        iam.generate_credential_report()
        content = None
        for _ in range(12):
            try:
                resp = iam.get_credential_report()
                content = resp["Content"].decode("utf-8")
                break
            except iam.exceptions.ReportNotPresent:
                time.sleep(0.5)
        if content is None:
            return {"error": "credential report not ready after retries"}
        lines = content.strip().splitlines()
        if len(lines) < 2:
            return {"error": "credential report too short"}
        header = lines[0].split(",")
        # Root is always first data row
        root_row = lines[1].split(",")
        data = dict(zip(header, root_row))
        return {
            "mfa_active": data.get("mfa_active") == "true",
            "access_key_1_active": data.get("access_key_1_active") == "true",
            "access_key_2_active": data.get("access_key_2_active") == "true",
            "password_last_used": data.get("password_last_used", "N/A"),
            "password_last_changed": data.get("password_last_changed", "N/A"),
        }
    except Exception as e:
        return {"error": str(e)}


def _get_users_with_details(iam) -> list:
    users = []
    try:
        paginator = iam.get_paginator("list_users")
        now = datetime.now(timezone.utc)
        for page in paginator.paginate():
            for u in page["Users"]:
                uname = u["UserName"]
                user_info = {
                    "username": uname,
                    "arn": u["Arn"],
                    "created": str(u.get("CreateDate", "")),
                    "password_last_used": str(u.get("PasswordLastUsed", "never")),
                    "mfa_enabled": False,
                    "access_keys": [],
                    "attached_policies": [],
                    "inline_policies": [],
                    "groups": [],
                }

                # MFA devices
                try:
                    mfa = iam.list_mfa_devices(UserName=uname)
                    user_info["mfa_enabled"] = len(mfa["MFADevices"]) > 0
                except Exception:
                    pass

                # Access keys
                try:
                    keys = iam.list_access_keys(UserName=uname)
                    for k in keys["AccessKeyMetadata"]:
                        age_days = (now - k["CreateDate"].replace(tzinfo=timezone.utc)).days
                        user_info["access_keys"].append({
                            "key_id": k["AccessKeyId"][-4:] + "****",
                            "status": k["Status"],
                            "created": str(k["CreateDate"]),
                            "age_days": age_days,
                            "stale": age_days > ACCESS_KEY_WARN_DAYS,
                            "critical_age": age_days > ACCESS_KEY_CRITICAL_DAYS,
                        })
                except Exception:
                    pass

                # Attached managed policies
                try:
                    pols = iam.list_attached_user_policies(UserName=uname)
                    user_info["attached_policies"] = [
                        p["PolicyArn"] for p in pols["AttachedPolicies"]
                    ]
                except Exception:
                    pass

                # Inline policies
                try:
                    inl = iam.list_user_policies(UserName=uname)
                    user_info["inline_policies"] = inl.get("PolicyNames", [])
                except Exception:
                    pass

                # Groups
                try:
                    grps = iam.list_groups_for_user(UserName=uname)
                    user_info["groups"] = [g["GroupName"] for g in grps["Groups"]]
                except Exception:
                    pass

                users.append(user_info)
    except Exception as e:
        return [{"error": str(e)}]
    return users


def _get_overprivileged_roles(iam) -> list:
    """Find roles with * actions or admin policies attached."""
    results = []
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                rname = role["RoleName"]
                issues = []

                # Attached managed policies
                try:
                    attached = iam.list_attached_role_policies(RoleName=rname)
                    for pol in attached["AttachedPolicies"]:
                        if pol["PolicyArn"] in OVERPRIVILEGED_MANAGED_POLICIES:
                            issues.append(f"Admin policy attached: {pol['PolicyArn']}")
                except Exception:
                    pass

                # Check trust policy for overly broad principals
                trust = role.get("AssumeRolePolicyDocument", {})
                for stmt in trust.get("Statement", []):
                    principal = stmt.get("Principal", {})
                    if principal == "*" or principal.get("AWS") == "*":
                        issues.append("Trust policy allows any principal (*)")

                if issues:
                    results.append({
                        "role_name": rname,
                        "arn": role["Arn"],
                        "issues": issues,
                    })
    except Exception as e:
        return [{"error": str(e)}]
    return results


def _get_groups_summary(iam) -> list:
    groups = []
    try:
        paginator = iam.get_paginator("list_groups")
        for page in paginator.paginate():
            for g in page["Groups"]:
                groups.append({
                    "name": g["GroupName"],
                    "arn": g["Arn"],
                })
    except Exception as e:
        return [{"error": str(e)}]
    return groups


def _find_admin_policy_attachments(iam) -> list:
    """Return all entities (users/groups/roles) with AdministratorAccess attached."""
    results = []
    try:
        for policy_arn in OVERPRIVILEGED_MANAGED_POLICIES:
            try:
                paginator = iam.get_paginator("list_entities_for_policy")
                for page in paginator.paginate(PolicyArn=policy_arn):
                    for u in page.get("PolicyUsers", []):
                        results.append({"type": "user", "name": u["UserName"], "policy": policy_arn})
                    for g in page.get("PolicyGroups", []):
                        results.append({"type": "group", "name": g["GroupName"], "policy": policy_arn})
                    for r in page.get("PolicyRoles", []):
                        results.append({"type": "role", "name": r["RoleName"], "policy": policy_arn})
            except Exception:
                pass
    except Exception as e:
        return [{"error": str(e)}]
    return results
