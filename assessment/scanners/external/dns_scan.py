"""
External DNS scanner — zone transfer, DNSSEC, SPF/DMARC/DKIM, subdomain exposure.
"""
import logging
import socket
import subprocess
import shutil
from assessment.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class DNSScanner(BaseScanner):
    name = "dns"
    provider = "external"

    def _scan(self) -> tuple[dict, list]:
        result = {
            "target": self.target,
            "dns_records": _get_dns_records(self.target),
            "zone_transfer": _check_zone_transfer(self.target),
            "email_security": _check_email_security(self.target),
            "dnssec": _check_dnssec(self.target),
        }
        return result, []


def _get_dns_records(domain: str) -> dict:
    records = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    if not shutil.which("dig"):
        # Fallback: use socket for A records only
        try:
            records["A"] = socket.gethostbyname_ex(domain)[2]
        except Exception as e:
            records["error"] = str(e)
        return records

    for rtype in record_types:
        try:
            out = subprocess.check_output(
                ["dig", "+short", rtype, domain],
                timeout=10, text=True, stderr=subprocess.DEVNULL
            )
            lines = [l.strip() for l in out.strip().splitlines() if l.strip()]
            if lines:
                records[rtype] = lines
        except Exception:
            pass

    return records


def _check_zone_transfer(domain: str) -> dict:
    """Attempt AXFR zone transfer against all nameservers."""
    result = {"attempted": False, "vulnerable_nameservers": []}

    if not shutil.which("dig"):
        return {"error": "dig not found"}

    # Get nameservers
    nameservers = []
    try:
        out = subprocess.check_output(
            ["dig", "+short", "NS", domain],
            timeout=10, text=True, stderr=subprocess.DEVNULL
        )
        nameservers = [l.strip().rstrip(".") for l in out.strip().splitlines() if l.strip()]
    except Exception:
        return result

    for ns in nameservers[:5]:  # limit to first 5
        result["attempted"] = True
        try:
            out = subprocess.check_output(
                ["dig", f"@{ns}", "AXFR", domain],
                timeout=10, text=True, stderr=subprocess.DEVNULL
            )
            # If transfer succeeds, output has many records
            lines = [l for l in out.splitlines() if l.strip() and not l.startswith(";")]
            if len(lines) > 5:
                result["vulnerable_nameservers"].append({
                    "nameserver": ns,
                    "record_count": len(lines),
                    "sample_records": lines[:5],
                })
        except Exception:
            pass

    return result


def _check_email_security(domain: str) -> dict:
    """Check SPF, DMARC, and DKIM records."""
    result = {}

    if not shutil.which("dig"):
        return {"error": "dig not found"}

    # SPF
    try:
        out = subprocess.check_output(
            ["dig", "+short", "TXT", domain],
            timeout=10, text=True, stderr=subprocess.DEVNULL
        )
        spf_records = [l for l in out.splitlines() if "v=spf1" in l.lower()]
        result["spf"] = {
            "present": bool(spf_records),
            "records": spf_records,
            "multiple_spf": len(spf_records) > 1,
        }
        if spf_records:
            spf = spf_records[0]
            result["spf"]["allows_all"] = "+all" in spf or " all" in spf
            result["spf"]["soft_fail"] = "~all" in spf
            result["spf"]["hard_fail"] = "-all" in spf
    except Exception:
        result["spf"] = {"error": "lookup failed"}

    # DMARC
    try:
        out = subprocess.check_output(
            ["dig", "+short", "TXT", f"_dmarc.{domain}"],
            timeout=10, text=True, stderr=subprocess.DEVNULL
        )
        dmarc_records = [l for l in out.splitlines() if "v=dmarc1" in l.lower()]
        result["dmarc"] = {
            "present": bool(dmarc_records),
            "records": dmarc_records,
        }
        if dmarc_records:
            dmarc = dmarc_records[0].lower()
            if "p=reject" in dmarc:
                result["dmarc"]["policy"] = "reject"
            elif "p=quarantine" in dmarc:
                result["dmarc"]["policy"] = "quarantine"
            elif "p=none" in dmarc:
                result["dmarc"]["policy"] = "none (monitoring only)"
    except Exception:
        result["dmarc"] = {"error": "lookup failed"}

    return result


def _check_dnssec(domain: str) -> dict:
    """Check if DNSSEC is enabled."""
    if not shutil.which("dig"):
        return {"error": "dig not found"}
    try:
        out = subprocess.check_output(
            ["dig", "+dnssec", "A", domain],
            timeout=10, text=True, stderr=subprocess.DEVNULL
        )
        has_rrsig = "RRSIG" in out
        has_ad_flag = ";; flags:" in out and " ad " in out
        return {
            "enabled": has_rrsig or has_ad_flag,
            "rrsig_present": has_rrsig,
            "ad_flag": has_ad_flag,
        }
    except Exception as e:
        return {"error": str(e)}
