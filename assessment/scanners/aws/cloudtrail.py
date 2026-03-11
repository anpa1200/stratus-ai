"""
AWS CloudTrail / GuardDuty / Security Hub / Config scanner.
"""
import logging
from assessment.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class CloudTrailScanner(BaseScanner):
    name = "cloudtrail"
    provider = "aws"

    def _scan(self) -> tuple[dict, list]:
        result = {}
        result["cloudtrail"] = _scan_cloudtrail(self.session, self.region)
        result["guardduty"] = _scan_guardduty(self.session, self.region)
        result["security_hub"] = _scan_security_hub(self.session, self.region)
        result["aws_config"] = _scan_aws_config(self.session, self.region)
        result["access_analyzer"] = _scan_access_analyzer(self.session, self.region)
        return result, []


def _scan_cloudtrail(session, region) -> dict:
    try:
        ct = session.client("cloudtrail", region_name=region)
        resp = ct.describe_trails(includeShadowTrails=False)
        trails = resp.get("trailList", [])
        result = {
            "trail_count": len(trails),
            "trails": [],
        }
        for trail in trails:
            trail_name = trail["Name"]
            trail_info = {
                "name": trail_name,
                "s3_bucket": trail.get("S3BucketName", ""),
                "is_multi_region": trail.get("IsMultiRegionTrail", False),
                "include_global_service_events": trail.get("IncludeGlobalServiceEvents", False),
                "has_custom_event_selectors": trail.get("HasCustomEventSelectors", False),
                "log_file_validation_enabled": trail.get("LogFileValidationEnabled", False),
                "cloudwatch_logs_arn": trail.get("CloudWatchLogsLogGroupArn"),
            }

            # Get trail status (logging enabled?)
            try:
                status = ct.get_trail_status(Name=trail["TrailARN"])
                trail_info["logging_enabled"] = status.get("IsLogging", False)
                trail_info["latest_delivery_time"] = str(status.get("LatestDeliveryTime", ""))
            except Exception:
                trail_info["logging_enabled"] = "unknown"

            result["trails"].append(trail_info)

        if not trails:
            result["note"] = "No CloudTrail trails found in this region"

        return result
    except Exception as e:
        return {"error": str(e)}


def _scan_guardduty(session, region) -> dict:
    try:
        gd = session.client("guardduty", region_name=region)
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            return {"enabled": False, "note": "GuardDuty not enabled in this region"}

        result = {"enabled": True, "detectors": []}
        for det_id in detectors:
            det = gd.get_detector(DetectorId=det_id)
            detector_info = {
                "detector_id": det_id,
                "status": det.get("Status"),
                "finding_publishing_frequency": det.get("FindingPublishingFrequency"),
                "data_sources": det.get("DataSources", {}),
            }

            # Get high/critical findings count
            try:
                findings = gd.list_findings(
                    DetectorId=det_id,
                    FindingCriteria={
                        "Criterion": {
                            "severity": {"Gte": 7}  # HIGH and CRITICAL
                        }
                    }
                )
                detector_info["high_critical_finding_count"] = len(findings.get("FindingIds", []))
            except Exception:
                pass

            result["detectors"].append(detector_info)

        return result
    except Exception as e:
        return {"error": str(e)}


def _scan_security_hub(session, region) -> dict:
    try:
        sh = session.client("securityhub", region_name=region)
        sh.describe_hub()  # raises if not enabled
        result = {"enabled": True}

        # Get failed controls count
        try:
            findings = sh.get_findings(
                Filters={
                    "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
                    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                    "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
                },
                MaxResults=100,
            )
            result["active_failed_findings_sample"] = len(findings.get("Findings", []))
        except Exception:
            pass

        return result
    except Exception as e:
        if "not subscribed" in str(e).lower() or "InvalidAccessException" in str(e):
            return {"enabled": False, "note": "Security Hub not enabled"}
        return {"error": str(e)}


def _scan_aws_config(session, region) -> dict:
    try:
        cfg = session.client("config", region_name=region)
        recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
        if not recorders:
            return {"enabled": False}

        recorder = recorders[0]
        status_resp = cfg.describe_configuration_recorder_status()
        statuses = status_resp.get("ConfigurationRecordersStatus", [{}])
        recording = statuses[0].get("recording", False) if statuses else False

        return {
            "enabled": True,
            "recording": recording,
            "recorder_name": recorder.get("name"),
            "all_supported": recorder.get("recordingGroup", {}).get("allSupported", False),
            "include_global_resource_types": recorder.get("recordingGroup", {}).get(
                "includeGlobalResourceTypes", False
            ),
        }
    except Exception as e:
        return {"error": str(e)}


def _scan_access_analyzer(session, region) -> dict:
    try:
        aa = session.client("accessanalyzer", region_name=region)
        analyzers = aa.list_analyzers().get("analyzers", [])
        if not analyzers:
            return {"enabled": False, "note": "IAM Access Analyzer not enabled in this region"}

        result = {"enabled": True, "analyzers": []}
        for analyzer in analyzers:
            info = {
                "name": analyzer["name"],
                "type": analyzer["type"],
                "status": analyzer["status"],
            }
            # Get active findings
            try:
                findings = aa.list_findings(
                    analyzerArn=analyzer["arn"],
                    Filter={"status": {"eq": ["ACTIVE"]}},
                    maxResults=50,
                )
                info["active_findings_count"] = len(findings.get("findings", []))
                info["active_findings_sample"] = [
                    {
                        "resource": f.get("resource"),
                        "resource_type": f.get("resourceType"),
                        "finding_type": f.get("findingType") if "findingType" in f else f.get("status"),
                    }
                    for f in findings.get("findings", [])[:10]
                ]
            except Exception:
                pass
            result["analyzers"].append(info)

        return result
    except Exception as e:
        return {"error": str(e)}
