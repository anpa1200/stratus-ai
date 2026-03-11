"""
AWS RDS scanner — public accessibility, encryption, auto backups, version compliance.
"""
import logging
from assessment.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class RDSScanner(BaseScanner):
    name = "rds"
    provider = "aws"

    def _scan(self) -> tuple[dict, list]:
        rds = self.session.client("rds", region_name=self.region)
        result = {}
        result["region"] = self.region
        result["instances"] = _scan_rds_instances(rds)
        result["snapshots_public"] = _scan_public_snapshots(rds)
        result["parameter_groups"] = _scan_parameter_groups(rds)
        return result, []


def _scan_rds_instances(rds) -> list:
    instances = []
    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                info = {
                    "identifier": db["DBInstanceIdentifier"],
                    "engine": db.get("Engine", ""),
                    "engine_version": db.get("EngineVersion", ""),
                    "instance_class": db.get("DBInstanceClass", ""),
                    "status": db.get("DBInstanceStatus", ""),
                    "publicly_accessible": db.get("PubliclyAccessible", False),
                    "encrypted": db.get("StorageEncrypted", False),
                    "multi_az": db.get("MultiAZ", False),
                    "auto_minor_version_upgrade": db.get("AutoMinorVersionUpgrade", False),
                    "backup_retention_days": db.get("BackupRetentionPeriod", 0),
                    "deletion_protection": db.get("DeletionProtection", False),
                    "iam_auth_enabled": db.get("IAMDatabaseAuthenticationEnabled", False),
                    "ca_certificate": db.get("CACertificateIdentifier", ""),
                    "endpoint": db.get("Endpoint", {}).get("Address"),
                    "port": db.get("Endpoint", {}).get("Port"),
                    "vpc_security_groups": [
                        sg["VpcSecurityGroupId"]
                        for sg in db.get("VpcSecurityGroups", [])
                    ],
                    "parameter_group": [
                        pg["DBParameterGroupName"]
                        for pg in db.get("DBParameterGroups", [])
                    ],
                }

                # Flag issues
                issues = []
                if info["publicly_accessible"]:
                    issues.append("publicly accessible")
                if not info["encrypted"]:
                    issues.append("storage not encrypted")
                if info["backup_retention_days"] == 0:
                    issues.append("automated backups disabled")
                if not info["deletion_protection"]:
                    issues.append("deletion protection disabled")

                info["issues"] = issues
                instances.append(info)
    except Exception as e:
        return [{"error": str(e)}]
    return instances


def _scan_public_snapshots(rds) -> list:
    """Find RDS snapshots with public restore permissions."""
    public_snaps = []
    try:
        paginator = rds.get_paginator("describe_db_snapshots")
        for page in paginator.paginate(SnapshotType="public"):
            for snap in page.get("DBSnapshots", []):
                public_snaps.append({
                    "snapshot_id": snap["DBSnapshotIdentifier"],
                    "db_identifier": snap.get("DBInstanceIdentifier"),
                    "engine": snap.get("Engine"),
                    "snapshot_create_time": str(snap.get("SnapshotCreateTime", "")),
                    "encrypted": snap.get("Encrypted", False),
                })
    except Exception as e:
        return [{"error": str(e)}]
    return public_snaps


def _scan_parameter_groups(rds) -> list:
    """Check for insecure database parameter settings."""
    issues = []
    # Interesting params to check (engine-specific)
    interesting_params = {
        "mysql": ["require_secure_transport", "log_output", "general_log", "slow_query_log"],
        "postgres": ["log_connections", "log_disconnections", "rds.force_ssl", "ssl"],
    }
    try:
        paginator = rds.get_paginator("describe_db_parameter_groups")
        for page in paginator.paginate():
            for pg in page["DBParameterGroups"]:
                pg_name = pg["DBParameterGroupName"]
                pg_family = pg.get("DBParameterGroupFamily", "").lower()

                params_to_check = []
                for engine, params in interesting_params.items():
                    if engine in pg_family:
                        params_to_check = params
                        break

                if not params_to_check:
                    continue

                try:
                    param_resp = rds.describe_db_parameters(DBParameterGroupName=pg_name)
                    for param in param_resp.get("Parameters", []):
                        if param["ParameterName"] in params_to_check:
                            issues.append({
                                "group": pg_name,
                                "family": pg_family,
                                "parameter": param["ParameterName"],
                                "value": param.get("ParameterValue", "not set"),
                                "source": param.get("Source", ""),
                            })
                except Exception:
                    pass
    except Exception as e:
        return [{"error": str(e)}]
    return issues
