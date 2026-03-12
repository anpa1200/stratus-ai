"""
GCP Cloud Functions scanner — public invoker, env vars, runtime, ingress.

Checks:
  - Functions with allUsers invoker (publicly callable without auth)
  - Deprecated runtimes
  - Environment variables with suspicious names (secrets in plain text)
  - Ingress settings (ALLOW_ALL vs ALLOW_INTERNAL_ONLY)
  - VPC connector not configured
"""
import logging
from assessment.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

DEPRECATED_RUNTIMES = {
    "nodejs6", "nodejs8", "nodejs10",
    "python27", "python37",
    "go111", "go113",
    "java8",
    "dotnet3",
    "ruby26", "ruby27",
    "php55", "php56",
}

SUSPICIOUS_ENV_PATTERNS = (
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "private_key", "credential", "auth", "access_key", "db_password",
    "db_url", "connection_string", "smtp_pass",
)


class GCPCloudFunctionsScanner(BaseScanner):
    name = "gcp_cloudfunctions"
    provider = "gcp"

    def _scan(self) -> tuple[dict, list]:
        project = self.session.project_id
        region = self.region or "-"
        result = {"project_id": project, "region": region}
        result["functions"] = _list_functions(self.session, project, region)
        return result, []


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _list_functions(session, project: str, region: str) -> list:
    try:
        cf = session.build("cloudfunctions", "v1")
        parent = f"projects/{project}/locations/{region}"
        functions = []
        request = cf.projects().locations().functions().list(parent=parent)
        while request is not None:
            resp = request.execute()
            for fn in resp.get("functions", []):
                functions.append(_parse_function(cf, project, fn))
            request = cf.projects().locations().functions().list_next(request, resp)
        return functions
    except Exception as e:
        return [{"error": str(e)}]


def _parse_function(cf, project: str, fn: dict) -> dict:
    name = fn.get("name", "")
    short_name = name.split("/")[-1]
    runtime = fn.get("runtime", "")
    status = fn.get("status", "")
    ingress = fn.get("ingressSettings", "ALLOW_ALL")
    trigger = fn.get("httpsTrigger", {})
    trigger_url = trigger.get("url", "")
    security_level = trigger.get("securityLevel", "SECURE_OPTIONAL")

    # Environment variables — check for suspicious names
    env_vars = fn.get("environmentVariables", {})
    suspicious_env = [
        k for k in env_vars
        if any(p in k.lower() for p in SUSPICIOUS_ENV_PATTERNS)
    ]

    # VPC connector
    vpc_connector = fn.get("vpcConnector", "")

    info = {
        "name": short_name,
        "full_name": name,
        "runtime": runtime,
        "status": status,
        "trigger_url": trigger_url,
        "security_level": security_level,
        "ingress_settings": ingress,
        "env_var_count": len(env_vars),
        "suspicious_env_vars": suspicious_env,
        "vpc_connector": vpc_connector,
        "deprecated_runtime": runtime.lower() in DEPRECATED_RUNTIMES,
        "issues": [],
    }

    # Check IAM policy for allUsers invoker
    info["public_invoker"] = False
    try:
        iam_resp = cf.projects().locations().functions().getIamPolicy(resource=name).execute()
        for binding in iam_resp.get("bindings", []):
            members = binding.get("members", [])
            role = binding.get("role", "")
            if "allUsers" in members and "invoker" in role.lower():
                info["public_invoker"] = True
                info["issues"].append(
                    f"allUsers has {role} — function callable without authentication"
                )
    except Exception as e:
        info["iam_error"] = str(e)

    # Build issues
    if security_level == "SECURE_OPTIONAL":
        info["issues"].append("security level SECURE_OPTIONAL (HTTP allowed, not forced HTTPS)")
    if ingress == "ALLOW_ALL":
        info["issues"].append("ingress ALLOW_ALL — callable from public internet")
    if info["deprecated_runtime"]:
        info["issues"].append(f"deprecated runtime: {runtime}")
    if suspicious_env:
        info["issues"].append(f"suspicious env var names (possible secrets in plaintext): {suspicious_env}")
    if not vpc_connector:
        info["issues"].append("no VPC connector — function cannot access private resources securely")

    return info
