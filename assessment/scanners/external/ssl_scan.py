"""
External SSL/TLS scanner — certificate validity, TLS version, cipher strength.
"""
import logging
import ssl
import socket
import subprocess
import shutil
from datetime import datetime, timezone
from assessment.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON",
    "MD5", "RC2", "IDEA",
]

WEAK_TLS_VERSIONS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]


class SSLScanner(BaseScanner):
    name = "ssl"
    provider = "external"

    def _scan(self) -> tuple[dict, list]:
        result = {
            "target": self.target,
            "https_443": _check_tls(self.target, 443),
            "https_8443": _check_tls(self.target, 8443),
        }
        if shutil.which("sslscan"):
            result["sslscan"] = _run_sslscan(self.target)
        return result, []


def _check_tls(hostname: str, port: int) -> dict:
    """Check TLS config using Python's ssl module."""
    info = {"hostname": hostname, "port": port}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                info["tls_version"] = ssock.version()
                info["cipher"] = ssock.cipher()

                # Certificate details
                not_after_str = cert.get("notAfter", "")
                not_before_str = cert.get("notBefore", "")
                now = datetime.now(timezone.utc)

                info["cert_subject"] = dict(x[0] for x in cert.get("subject", []))
                info["cert_issuer"] = dict(x[0] for x in cert.get("issuer", []))
                info["cert_not_before"] = not_before_str
                info["cert_not_after"] = not_after_str

                # Days until expiry
                try:
                    not_after = ssl.cert_time_to_seconds(not_after_str)
                    not_after_dt = datetime.fromtimestamp(not_after, tz=timezone.utc)
                    days_remaining = (not_after_dt - now).days
                    info["cert_days_remaining"] = days_remaining
                    info["cert_expired"] = days_remaining < 0
                    info["cert_expiring_soon"] = 0 < days_remaining < 30
                except Exception:
                    pass

                # SANs
                san_list = []
                for san_type, san_value in cert.get("subjectAltName", []):
                    san_list.append(f"{san_type}:{san_value}")
                info["san"] = san_list

                # Check TLS version
                tls_ver = ssock.version() or ""
                info["weak_tls_version"] = any(weak in tls_ver for weak in WEAK_TLS_VERSIONS)

                # Cipher suite check
                cipher_name = ssock.cipher()[0] if ssock.cipher() else ""
                info["weak_cipher"] = any(w in cipher_name.upper() for w in WEAK_CIPHERS)

    except ssl.SSLError as e:
        info["error"] = f"SSL error: {e}"
    except ConnectionRefusedError:
        info["error"] = "Connection refused"
    except socket.timeout:
        info["error"] = "Connection timeout"
    except OSError as e:
        info["error"] = str(e)
    except Exception as e:
        info["error"] = str(e)

    return info


def _run_sslscan(target: str) -> dict:
    try:
        out = subprocess.check_output(
            ["sslscan", "--no-colour", target],
            stderr=subprocess.DEVNULL,
            timeout=60,
            text=True,
        )
        # Parse key findings
        result = {"raw_output_lines": len(out.splitlines())}

        # Extract vulnerable protocols
        vulnerable = []
        for line in out.splitlines():
            for weak in WEAK_TLS_VERSIONS + ["RC4", "Export"]:
                if weak.lower() in line.lower() and "enabled" in line.lower():
                    vulnerable.append(line.strip())

        result["vulnerable_protocols_ciphers"] = vulnerable
        return result
    except Exception as e:
        return {"error": str(e)}
