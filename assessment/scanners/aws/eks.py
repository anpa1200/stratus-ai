"""
AWS EKS scanner — public API endpoint, auth mode, logging, node groups, secrets encryption.
"""
import logging
from assessment.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# EKS Kubernetes versions that are EOL
DEPRECATED_K8S_VERSIONS = {"1.23", "1.24", "1.25", "1.26", "1.27"}


class EKSScanner(BaseScanner):
    name = "eks"
    provider = "aws"

    def _scan(self) -> tuple[dict, list]:
        eks = self.session.client("eks", region_name=self.region)
        result = {
            "region": self.region,
            "clusters": _scan_clusters(eks),
        }
        return result, []


def _scan_clusters(eks) -> list:
    clusters = []
    try:
        paginator = eks.get_paginator("list_clusters")
        for page in paginator.paginate():
            for cluster_name in page["clusters"]:
                try:
                    detail = eks.describe_cluster(name=cluster_name)["cluster"]
                except Exception as e:
                    clusters.append({"name": cluster_name, "error": str(e)})
                    continue

                k8s_version = detail.get("version", "")
                endpoint_config = detail.get("resourcesVpcConfig", {})

                info = {
                    "name": cluster_name,
                    "arn": detail.get("arn", ""),
                    "status": detail.get("status", ""),
                    "kubernetes_version": k8s_version,
                    "deprecated_version": _is_deprecated_version(k8s_version),
                    # Endpoint access
                    "endpoint_public_access": endpoint_config.get("endpointPublicAccess", True),
                    "endpoint_private_access": endpoint_config.get("endpointPrivateAccess", False),
                    "public_access_cidrs": endpoint_config.get("publicAccessCidrs", ["0.0.0.0/0"]),
                    "endpoint_open_to_world": _is_open_to_world(
                        endpoint_config.get("endpointPublicAccess", True),
                        endpoint_config.get("publicAccessCidrs", ["0.0.0.0/0"]),
                    ),
                    # Logging
                    "logging": _parse_logging(detail.get("logging", {})),
                    # Encryption
                    "secrets_encryption": _check_secrets_encryption(detail.get("encryptionConfig", [])),
                    # Auth
                    "role_arn": detail.get("roleArn", ""),
                    # Node groups
                    "node_groups": _scan_node_groups(eks, cluster_name),
                }

                clusters.append(info)
    except Exception as e:
        return [{"error": str(e)}]
    return clusters


def _is_deprecated_version(version: str) -> bool:
    """Check if the major.minor version is deprecated."""
    if not version:
        return False
    parts = version.split(".")
    if len(parts) >= 2:
        major_minor = f"{parts[0]}.{parts[1]}"
        return major_minor in DEPRECATED_K8S_VERSIONS
    return False


def _is_open_to_world(public_access: bool, cidrs: list) -> bool:
    """Return True if endpoint is public and open to 0.0.0.0/0."""
    if not public_access:
        return False
    return "0.0.0.0/0" in cidrs or not cidrs


def _parse_logging(logging_config: dict) -> dict:
    """Extract which log types are enabled."""
    enabled = []
    disabled = []
    for cluster_log in logging_config.get("clusterLogging", []):
        types = cluster_log.get("types", [])
        if cluster_log.get("enabled"):
            enabled.extend(types)
        else:
            disabled.extend(types)
    return {
        "enabled_types": enabled,
        "disabled_types": disabled,
        "api_logging": "api" in enabled,
        "audit_logging": "audit" in enabled,
    }


def _check_secrets_encryption(encryption_config: list) -> dict:
    """Check if Kubernetes secrets are encrypted with KMS."""
    for entry in encryption_config:
        resources = entry.get("resources", [])
        if "secrets" in resources:
            provider = entry.get("provider", {})
            return {
                "enabled": True,
                "kms_key_arn": provider.get("keyArn", ""),
            }
    return {"enabled": False}


def _scan_node_groups(eks, cluster_name: str) -> list:
    """Scan EKS managed node groups for security issues."""
    node_groups = []
    try:
        paginator = eks.get_paginator("list_nodegroups")
        for page in paginator.paginate(clusterName=cluster_name):
            for ng_name in page["nodegroups"]:
                try:
                    ng = eks.describe_nodegroup(
                        clusterName=cluster_name, nodegroupName=ng_name
                    )["nodegroup"]
                    node_groups.append({
                        "name": ng_name,
                        "status": ng.get("status", ""),
                        "ami_type": ng.get("amiType", ""),
                        "instance_types": ng.get("instanceTypes", []),
                        "disk_size": ng.get("diskSize", 0),
                        "remote_access": bool(ng.get("remoteAccess")),
                        "remote_access_source_cidrs": (
                            ng.get("remoteAccess", {}).get("sourceSecurityGroups", [])
                        ),
                    })
                except Exception:
                    pass
    except Exception:
        pass
    return node_groups
