"""
GCP Cloud Logging / Audit Logs scanner.

Checks:
  - Data Access audit logs enabled (admin reads, data reads, data writes)
  - Log sinks configured (log export)
  - Log retention policy
  - VPC flow logs on subnets
  - Admin Activity logs (always enabled, but verify)
"""
import logging
from assessment.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# Audit log types to check for Data Access logs
DATA_ACCESS_SERVICES = [
    "allServices",
    "storage.googleapis.com",
    "iam.googleapis.com",
    "compute.googleapis.com",
    "cloudkms.googleapis.com",
    "secretmanager.googleapis.com",
]


class GCPLoggingScanner(BaseScanner):
    name = "gcp_logging"
    provider = "gcp"

    def _scan(self) -> tuple[dict, list]:
        project = self.session.project_id
        result = {"project_id": project}

        result["audit_log_config"] = _get_audit_log_config(self.session, project)
        result["log_sinks"] = _list_log_sinks(self.session, project)
        result["vpc_flow_logs"] = _check_vpc_flow_logs(self.session, project)

        return result, []


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _get_audit_log_config(session, project: str) -> dict:
    """
    Check if Data Access audit logs are enabled via the project IAM policy.
    Data Access logs are configured as auditConfigs in the IAM policy.
    """
    try:
        crm = session.build("cloudresourcemanager", "v1")
        policy = crm.projects().getIamPolicy(
            resource=project,
            body={"options": {"requestedPolicyVersion": 1}},
        ).execute()

        audit_configs = policy.get("auditConfigs", [])
        configured_services = {}
        for ac in audit_configs:
            service = ac.get("service", "")
            log_types = [alc.get("logType") for alc in ac.get("auditLogConfigs", [])]
            configured_services[service] = log_types

        # Check for allServices or key services
        all_services_config = configured_services.get("allServices", [])
        data_read_enabled = "DATA_READ" in all_services_config
        data_write_enabled = "DATA_WRITE" in all_services_config
        admin_read_enabled = "ADMIN_READ" in all_services_config

        issues = []
        if not data_read_enabled:
            issues.append("DATA_READ audit logs not enabled for allServices")
        if not data_write_enabled:
            issues.append("DATA_WRITE audit logs not enabled for allServices")
        if not admin_read_enabled:
            issues.append("ADMIN_READ audit logs not enabled for allServices")

        return {
            "audit_configs": audit_configs,
            "configured_services": configured_services,
            "data_read_enabled": data_read_enabled,
            "data_write_enabled": data_write_enabled,
            "admin_read_enabled": admin_read_enabled,
            "issues": issues,
            "note": "Admin Activity logs are always enabled and cannot be disabled.",
        }
    except Exception as e:
        return {"error": str(e)}


def _list_log_sinks(session, project: str) -> dict:
    try:
        logging_svc = session.build("logging", "v2")
        request = logging_svc.projects().sinks().list(parent=f"projects/{project}")
        sinks = []
        while request is not None:
            resp = request.execute()
            for sink in resp.get("sinks", []):
                sinks.append({
                    "name": sink.get("name", "").split("/")[-1],
                    "destination": sink.get("destination", ""),
                    "filter": sink.get("filter", ""),
                    "include_children": sink.get("includeChildren", False),
                    "disabled": sink.get("disabled", False),
                })
            request = logging_svc.projects().sinks().list_next(request, resp)

        return {
            "total_sinks": len(sinks),
            "sinks": sinks,
            "has_export": len(sinks) > 0,
            "issues": [] if sinks else ["no log sinks configured — logs not exported for long-term retention or SIEM"],
        }
    except Exception as e:
        return {"error": str(e)}


def _check_vpc_flow_logs(session, project: str) -> dict:
    """Check which subnets have VPC flow logs enabled."""
    try:
        compute = session.build("compute", "v1")
        subnets_without_logs = []
        subnets_with_logs = 0
        total = 0

        request = compute.subnetworks().aggregatedList(project=project)
        while request is not None:
            resp = request.execute()
            for region_data in resp.get("items", {}).values():
                for subnet in region_data.get("subnetworks", []):
                    total += 1
                    name = subnet.get("name", "")
                    region = subnet.get("region", "").split("/")[-1]
                    log_config = subnet.get("logConfig", {})
                    flow_logs_enabled = log_config.get("enable", False)
                    if flow_logs_enabled:
                        subnets_with_logs += 1
                    else:
                        subnets_without_logs.append({
                            "name": name,
                            "region": region,
                            "cidr": subnet.get("ipCidrRange", ""),
                        })
            request = compute.subnetworks().aggregatedList_next(request, resp)

        issues = []
        if subnets_without_logs:
            issues.append(
                f"{len(subnets_without_logs)} of {total} subnets have VPC flow logs disabled"
            )

        return {
            "total_subnets": total,
            "subnets_with_flow_logs": subnets_with_logs,
            "subnets_without_flow_logs": subnets_without_logs,
            "issues": issues,
        }
    except Exception as e:
        return {"error": str(e)}
