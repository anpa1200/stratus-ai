"""
GCP Compute Engine scanner — firewall rules, instances, public IPs, metadata.

Checks:
  - Firewall rules allowing SSH/RDP/MySQL/etc from 0.0.0.0/0
  - Instances with external (public) IP addresses
  - Instances using the default Compute service account
  - Instances with full cloud-platform API scope
  - Instances exposing SA key in metadata
  - OS Login configuration
  - Default VPC usage
"""
import logging
from assessment.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

SENSITIVE_PORTS = {
    "22": "SSH",
    "3389": "RDP",
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "6379": "Redis",
    "27017": "MongoDB",
    "2375": "Docker API (unencrypted)",
    "9200": "Elasticsearch",
    "5601": "Kibana",
    "8080": "HTTP-alt",
    "8443": "HTTPS-alt",
}

FULL_ACCESS_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


class GCPComputeScanner(BaseScanner):
    name = "gcp_compute"
    provider = "gcp"

    def _scan(self) -> tuple[dict, list]:
        project = self.session.project_id
        result = {"project_id": project, "region": self.region}

        result["firewall_rules"] = _list_firewall_rules(self.session, project)
        result["risky_firewall_rules"] = _find_risky_firewall_rules(result["firewall_rules"])
        result["instances"] = _list_instances(self.session, project, self.region)
        result["default_vpc_exists"] = _check_default_vpc(self.session, project)

        return result, []


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _list_firewall_rules(session, project: str) -> list:
    try:
        compute = session.build("compute", "v1")
        rules = []
        request = compute.firewalls().list(project=project)
        while request is not None:
            resp = request.execute()
            for rule in resp.get("items", []):
                rules.append({
                    "name": rule.get("name", ""),
                    "direction": rule.get("direction", ""),
                    "priority": rule.get("priority", 1000),
                    "disabled": rule.get("disabled", False),
                    "source_ranges": rule.get("sourceRanges", []),
                    "destination_ranges": rule.get("destinationRanges", []),
                    "allowed": rule.get("allowed", []),
                    "denied": rule.get("denied", []),
                    "target_tags": rule.get("targetTags", []),
                    "target_service_accounts": rule.get("targetServiceAccounts", []),
                    "network": rule.get("network", "").split("/")[-1],
                    "log_config_enabled": rule.get("logConfig", {}).get("enable", False),
                })
            request = compute.firewalls().list_next(request, resp)
        return rules
    except Exception as e:
        return [{"error": str(e)}]


def _find_risky_firewall_rules(rules: list) -> list:
    risky = []
    for rule in rules:
        if rule.get("error") or rule.get("direction") != "INGRESS":
            continue
        if rule.get("disabled"):
            continue
        sources = rule.get("source_ranges", [])
        if "0.0.0.0/0" not in sources and "::/0" not in sources:
            continue

        # Open to the internet — check what ports are allowed
        allowed_ports = []
        for allow in rule.get("allowed", []):
            protocol = allow.get("IPProtocol", "")
            ports = allow.get("ports", [])
            if protocol in ("all", "tcp", "udp") and not ports:
                # All ports open
                allowed_ports.append(f"{protocol}:ALL")
            else:
                for port in ports:
                    label = SENSITIVE_PORTS.get(str(port), "")
                    allowed_ports.append(f"{protocol}:{port}" + (f" ({label})" if label else ""))

        if allowed_ports:
            rule_copy = dict(rule)
            rule_copy["open_to_internet_ports"] = allowed_ports
            rule_copy["issue"] = f"Ingress from 0.0.0.0/0: {', '.join(allowed_ports)}"
            risky.append(rule_copy)

    return risky


def _list_instances(session, project: str, region: str) -> list:
    try:
        compute = session.build("compute", "v1")
        instances = []

        # Use aggregated list to get all zones at once
        request = compute.instances().aggregatedList(project=project)
        while request is not None:
            resp = request.execute()
            for zone_data in resp.get("items", {}).values():
                for inst in zone_data.get("instances", []):
                    instance_info = _parse_instance(inst, project)
                    instances.append(instance_info)
            request = compute.instances().aggregatedList_next(request, resp)
        return instances
    except Exception as e:
        return [{"error": str(e)}]


def _parse_instance(inst: dict, project: str) -> dict:
    name = inst.get("name", "")
    status = inst.get("status", "")
    zone = inst.get("zone", "").split("/")[-1]
    machine_type = inst.get("machineType", "").split("/")[-1]

    # Network interfaces — check for public IP
    public_ips = []
    for nic in inst.get("networkInterfaces", []):
        for access_config in nic.get("accessConfigs", []):
            nat_ip = access_config.get("natIP", "")
            if nat_ip:
                public_ips.append(nat_ip)

    # Service account and scopes
    service_accounts = []
    has_full_scope = False
    is_default_sa = False
    for sa in inst.get("serviceAccounts", []):
        sa_email = sa.get("email", "")
        scopes = sa.get("scopes", [])
        service_accounts.append({"email": sa_email, "scopes": scopes})
        if FULL_ACCESS_SCOPE in scopes:
            has_full_scope = True
        if sa_email.endswith("-compute@developer.gserviceaccount.com"):
            is_default_sa = True

    # Metadata — check for sensitive keys
    metadata_keys = []
    sensitive_metadata = []
    for item in inst.get("metadata", {}).get("items", []):
        key = item.get("key", "")
        metadata_keys.append(key)
        val = item.get("value", "")
        if any(s in key.lower() for s in ("key", "secret", "password", "token", "credential")):
            # Don't log the value, just flag the key
            sensitive_metadata.append(key)

    # OS Login and legacy metadata endpoint
    os_login_enabled = None
    legacy_metadata_enabled = True  # default: legacy endpoint enabled unless explicitly disabled
    for item in inst.get("metadata", {}).get("items", []):
        k = item.get("key", "")
        v = item.get("value", "").lower()
        if k == "enable-oslogin":
            os_login_enabled = v == "true"
        if k == "disable-legacy-endpoints":
            legacy_metadata_enabled = v != "true"

    # Shielded VM
    shielded_config = inst.get("shieldedInstanceConfig", {})

    issues = []
    if public_ips:
        issues.append(f"public IP: {', '.join(public_ips)}")
    if has_full_scope:
        issues.append("full cloud-platform API scope (allows all GCP API access)")
    if is_default_sa and has_full_scope:
        issues.append("running as default Compute SA with full scope (high-risk combination)")
    if sensitive_metadata:
        issues.append(f"sensitive metadata keys: {', '.join(sensitive_metadata)}")
    if os_login_enabled is False:
        issues.append("OS Login disabled (SSH key-based auth active)")
    if legacy_metadata_enabled:
        issues.append("legacy metadata endpoint enabled (v0.1/v1beta1 accessible without Metadata-Flavor header)")

    return {
        "name": name,
        "zone": zone,
        "status": status,
        "machine_type": machine_type,
        "public_ips": public_ips,
        "has_public_ip": bool(public_ips),
        "service_accounts": service_accounts,
        "has_full_api_scope": has_full_scope,
        "is_default_sa": is_default_sa,
        "metadata_keys": metadata_keys,
        "sensitive_metadata_keys": sensitive_metadata,
        "os_login_enabled": os_login_enabled,
        "legacy_metadata_endpoint_enabled": legacy_metadata_enabled,
        "shielded_vm_secure_boot": shielded_config.get("enableSecureBoot", False),
        "shielded_vm_vtpm": shielded_config.get("enableVtpm", False),
        "issues": issues,
    }


def _check_default_vpc(session, project: str) -> dict:
    try:
        compute = session.build("compute", "v1")
        resp = compute.networks().get(project=project, network="default").execute()
        return {
            "exists": True,
            "name": resp.get("name", "default"),
            "auto_create_subnetworks": resp.get("autoCreateSubnetworks", False),
            "issue": "Default VPC exists — should be deleted in production environments",
        }
    except Exception as e:
        err_str = str(e)
        if "404" in err_str or "not found" in err_str.lower():
            return {"exists": False}
        return {"exists": None, "error": err_str}
