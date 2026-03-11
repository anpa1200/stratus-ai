"""
AWS EC2 scanner — security groups, instances, IMDSv2, EBS encryption, public snapshots.
"""
import logging
from assessment.scanners.base import BaseScanner
from assessment.config import SENSITIVE_PORTS

logger = logging.getLogger(__name__)


class EC2Scanner(BaseScanner):
    name = "ec2"
    provider = "aws"

    def _scan(self) -> tuple[dict, list]:
        ec2 = self.session.client("ec2", region_name=self.region)
        result = {}
        result["region"] = self.region
        result["security_groups"] = _scan_security_groups(ec2)
        result["instances"] = _scan_instances(ec2)
        result["public_snapshots"] = _scan_public_snapshots(ec2)
        result["ebs_encryption_default"] = _check_ebs_encryption_default(ec2)
        result["key_pairs"] = _list_key_pairs(ec2)
        result["vpc_summary"] = _scan_vpcs(ec2)
        return result, []


def _scan_security_groups(ec2) -> list:
    groups = []
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                info = {
                    "group_id": sg["GroupId"],
                    "group_name": sg["GroupName"],
                    "vpc_id": sg.get("VpcId", ""),
                    "description": sg.get("Description", ""),
                    "inbound_open_to_world": [],
                    "inbound_sensitive_ports_open": [],
                }

                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 65535)
                    protocol = rule.get("IpProtocol", "")

                    # Check for 0.0.0.0/0 or ::/0
                    for ip_range in rule.get("IpRanges", []) + rule.get("Ipv6Ranges", []):
                        cidr = ip_range.get("CidrIp", ip_range.get("CidrIpv6", ""))
                        if cidr in ("0.0.0.0/0", "::/0"):
                            entry = {
                                "protocol": protocol,
                                "port_range": f"{from_port}-{to_port}" if from_port != to_port else str(from_port),
                                "cidr": cidr,
                            }
                            info["inbound_open_to_world"].append(entry)

                            # Check for sensitive ports
                            if protocol in ("tcp", "-1"):
                                for port, service in SENSITIVE_PORTS.items():
                                    if protocol == "-1" or (from_port <= port <= to_port):
                                        info["inbound_sensitive_ports_open"].append(
                                            f"port {port} ({service})"
                                        )

                groups.append(info)
    except Exception as e:
        return [{"error": str(e)}]
    return groups


def _scan_instances(ec2) -> list:
    instances = []
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    if inst["State"]["Name"] == "terminated":
                        continue

                    name = ""
                    for tag in inst.get("Tags", []):
                        if tag["Key"] == "Name":
                            name = tag["Value"]

                    # Check IMDSv2 enforcement
                    metadata_options = inst.get("MetadataOptions", {})
                    imdsv2_required = metadata_options.get("HttpTokens", "optional") == "required"

                    info = {
                        "instance_id": inst["InstanceId"],
                        "name": name,
                        "instance_type": inst.get("InstanceType", ""),
                        "state": inst["State"]["Name"],
                        "public_ip": inst.get("PublicIpAddress"),
                        "public_dns": inst.get("PublicDnsName"),
                        "has_public_ip": bool(inst.get("PublicIpAddress")),
                        "imdsv2_required": imdsv2_required,
                        "iam_instance_profile": inst.get("IamInstanceProfile", {}).get("Arn"),
                        "security_groups": [sg["GroupId"] for sg in inst.get("SecurityGroups", [])],
                        "key_name": inst.get("KeyName"),
                        "monitoring": inst.get("Monitoring", {}).get("State", "disabled"),
                        "ebs_optimized": inst.get("EbsOptimized", False),
                    }

                    # Check EBS volumes for encryption
                    unencrypted_volumes = []
                    for mapping in inst.get("BlockDeviceMappings", []):
                        ebs = mapping.get("Ebs", {})
                        vol_id = ebs.get("VolumeId")
                        if vol_id:
                            try:
                                vol_resp = ec2.describe_volumes(VolumeIds=[vol_id])
                                for vol in vol_resp["Volumes"]:
                                    if not vol.get("Encrypted", False):
                                        unencrypted_volumes.append(vol_id)
                            except Exception:
                                pass
                    info["unencrypted_volumes"] = unencrypted_volumes

                    instances.append(info)
    except Exception as e:
        return [{"error": str(e)}]
    return instances


def _scan_public_snapshots(ec2) -> list:
    """Find EBS snapshots with public restore permissions."""
    public_snaps = []
    try:
        # Only check snapshots owned by this account that are public
        sts = ec2._endpoint.host  # placeholder
        paginator = ec2.get_paginator("describe_snapshots")
        # Use RestorableByUserIds=all to find public ones owned by this account
        # This requires knowing account ID
        import boto3
        account_id = boto3.client("sts").get_caller_identity()["Account"]
        for page in paginator.paginate(OwnerIds=[account_id]):
            for snap in page["Snapshots"]:
                try:
                    attrs = ec2.describe_snapshot_attribute(
                        SnapshotId=snap["SnapshotId"],
                        Attribute="createVolumePermission"
                    )
                    perms = attrs.get("CreateVolumePermissions", [])
                    for p in perms:
                        if p.get("Group") == "all":
                            public_snaps.append({
                                "snapshot_id": snap["SnapshotId"],
                                "description": snap.get("Description", ""),
                                "start_time": str(snap.get("StartTime", "")),
                                "volume_size": snap.get("VolumeSize"),
                            })
                            break
                except Exception:
                    pass
    except Exception as e:
        return [{"error": str(e)}]
    return public_snaps


def _check_ebs_encryption_default(ec2) -> dict:
    try:
        resp = ec2.get_ebs_encryption_by_default()
        return {
            "enabled": resp.get("EbsEncryptionByDefault", False),
        }
    except Exception as e:
        return {"error": str(e)}


def _list_key_pairs(ec2) -> list:
    try:
        resp = ec2.describe_key_pairs()
        return [
            {"name": kp["KeyName"], "fingerprint": kp.get("KeyFingerprint", "")}
            for kp in resp.get("KeyPairs", [])
        ]
    except Exception as e:
        return [{"error": str(e)}]


def _scan_vpcs(ec2) -> list:
    vpcs = []
    try:
        resp = ec2.describe_vpcs()
        for vpc in resp.get("Vpcs", []):
            name = ""
            for tag in vpc.get("Tags", []):
                if tag["Key"] == "Name":
                    name = tag["Value"]
            info = {
                "vpc_id": vpc["VpcId"],
                "name": name,
                "cidr": vpc["CidrBlock"],
                "is_default": vpc.get("IsDefault", False),
                "flow_logs_enabled": False,
            }
            # Check flow logs
            try:
                fl = ec2.describe_flow_logs(
                    Filters=[{"Name": "resource-id", "Values": [vpc["VpcId"]]}]
                )
                info["flow_logs_enabled"] = len(fl.get("FlowLogs", [])) > 0
            except Exception:
                pass
            vpcs.append(info)
    except Exception as e:
        return [{"error": str(e)}]
    return vpcs
