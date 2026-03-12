"""
GCP Cloud Run scanner — public access, hardcoded credentials in env vars, ingress.

Checks:
  - Services with allUsers invoker (no authentication required)
  - Environment variables with hardcoded credentials/secrets
  - Ingress configuration (all traffic vs internal)
  - Services using default Compute service account
"""
import logging
from assessment.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

SUSPICIOUS_ENV_PATTERNS = (
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "private_key", "credential", "auth", "access_key", "db_password",
    "db_url", "connection_string", "smtp_pass", "database_url",
)


class GCPCloudRunScanner(BaseScanner):
    name = "gcp_cloudrun"
    provider = "gcp"

    def _scan(self) -> tuple[dict, list]:
        project = self.session.project_id
        region = self.region or "-"
        result = {"project_id": project, "region": region}
        result["services"] = _list_services(self.session, project, region)
        return result, []


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _list_services(session, project: str, region: str) -> list:
    try:
        run = session.build("run", "v1")
        parent = f"projects/{project}/locations/{region}"
        services = []
        request = run.projects().locations().services().list(parent=parent)
        while request is not None:
            resp = request.execute()
            for svc in resp.get("items", []):
                services.append(_parse_service(run, project, region, svc))
            request = run.projects().locations().services().list_next(request, resp)
        return services
    except Exception as e:
        return [{"error": str(e)}]


def _parse_service(run, project: str, region: str, svc: dict) -> dict:
    metadata = svc.get("metadata", {})
    name = metadata.get("name", "")
    namespace = metadata.get("namespace", project)
    annotations = metadata.get("annotations", {})
    ingress = annotations.get("run.googleapis.com/ingress", "all")

    spec = svc.get("spec", {})
    template = spec.get("template", {})
    container_spec = template.get("spec", {})
    containers = container_spec.get("containers", [])

    # Service account
    service_account = container_spec.get("serviceAccountName", "")

    # URL from status
    status = svc.get("status", {})
    url = status.get("url", "")
    ready = any(
        c.get("type") == "Ready" and c.get("status") == "True"
        for c in status.get("conditions", [])
    )

    # Environment variables from all containers
    suspicious_env = []
    total_env_count = 0
    for container in containers:
        for env in container.get("env", []):
            total_env_count += 1
            env_name = env.get("name", "")
            if any(p in env_name.lower() for p in SUSPICIOUS_ENV_PATTERNS):
                # Check if it's a plain value (not a secret ref)
                if "value" in env and not env.get("valueFrom"):
                    suspicious_env.append(env_name)

    info = {
        "name": name,
        "namespace": namespace,
        "url": url,
        "ready": ready,
        "ingress": ingress,
        "service_account": service_account,
        "total_env_vars": total_env_count,
        "suspicious_env_vars": suspicious_env,
        "public_invoker": False,
        "issues": [],
    }

    # Check IAM policy for allUsers invoker
    resource = f"projects/{namespace}/locations/{region}/services/{name}"
    try:
        iam_resp = run.projects().locations().services().getIamPolicy(resource=resource).execute()
        for binding in iam_resp.get("bindings", []):
            members = binding.get("members", [])
            role = binding.get("role", "")
            if "allUsers" in members and "invoker" in role.lower():
                info["public_invoker"] = True
                info["issues"].append(
                    f"allUsers has {role} — service callable without authentication"
                )
    except Exception as e:
        info["iam_error"] = str(e)

    # Build issues
    if ingress == "all":
        info["issues"].append("ingress=all — service accepts traffic from public internet")
    if suspicious_env:
        info["issues"].append(
            f"potential hardcoded credentials in env vars: {suspicious_env}"
        )
    if not service_account:
        info["issues"].append("no explicit service account — using default Compute SA")

    return info
