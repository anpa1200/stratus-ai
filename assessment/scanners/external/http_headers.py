"""
External HTTP security headers scanner.
"""
import logging
import requests
import urllib3
from assessment.scanners.base import BaseScanner
from assessment.config import EXPECTED_SECURITY_HEADERS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


class HTTPHeadersScanner(BaseScanner):
    name = "http_headers"
    provider = "external"

    def _scan(self) -> tuple[dict, list]:
        result = {"target": self.target}
        result["https"] = _check_headers(f"https://{self.target}")
        result["http"] = _check_http_redirect(f"http://{self.target}")
        return result, []


def _check_headers(url: str) -> dict:
    info = {"url": url}
    try:
        resp = requests.get(
            url,
            timeout=15,
            verify=False,  # cert issues handled by ssl_scan
            allow_redirects=True,
            headers={"User-Agent": "CloudAudit/1.0 Security Assessment"},
        )
        info["status_code"] = resp.status_code
        info["final_url"] = resp.url

        headers = {k.lower(): v for k, v in resp.headers.items()}
        info["server"] = resp.headers.get("Server", "not disclosed")
        info["x_powered_by"] = resp.headers.get("X-Powered-By", "not disclosed")

        # Check expected security headers (case-insensitive)
        missing = []
        present = {}
        for h in EXPECTED_SECURITY_HEADERS:
            val = resp.headers.get(h)
            if val:
                present[h] = val
            else:
                missing.append(h)

        info["missing_security_headers"] = missing
        info["present_security_headers"] = present

        # HSTS check
        hsts = resp.headers.get("Strict-Transport-Security", "")
        if hsts:
            info["hsts_max_age"] = _parse_hsts_max_age(hsts)
            info["hsts_include_subdomains"] = "includeSubDomains" in hsts
            info["hsts_preload"] = "preload" in hsts
        else:
            info["hsts_max_age"] = 0

        # Check for sensitive info disclosure in headers
        info["version_disclosure"] = _check_version_disclosure(resp.headers)

        # Cookie security
        info["cookies"] = _check_cookies(resp)

    except requests.exceptions.SSLError as e:
        info["error"] = f"SSL error: {e}"
    except requests.exceptions.ConnectionError as e:
        info["error"] = f"Connection error: {e}"
    except requests.exceptions.Timeout:
        info["error"] = "Request timeout"
    except Exception as e:
        info["error"] = str(e)

    return info


def _check_http_redirect(url: str) -> dict:
    """Check if HTTP redirects to HTTPS."""
    info = {"url": url}
    try:
        resp = requests.get(
            url,
            timeout=10,
            allow_redirects=False,
            headers={"User-Agent": "CloudAudit/1.0 Security Assessment"},
        )
        info["status_code"] = resp.status_code
        location = resp.headers.get("Location", "")
        info["redirects_to_https"] = location.startswith("https://")
        info["redirect_location"] = location
    except requests.exceptions.ConnectionError:
        info["http_not_listening"] = True
    except Exception as e:
        info["error"] = str(e)
    return info


def _parse_hsts_max_age(hsts: str) -> int:
    """Extract max-age value from HSTS header."""
    for part in hsts.split(";"):
        part = part.strip()
        if part.lower().startswith("max-age="):
            try:
                return int(part.split("=", 1)[1].strip())
            except Exception:
                pass
    return 0


def _check_version_disclosure(headers) -> list:
    """Find headers that leak software versions."""
    disclosures = []
    version_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]
    import re
    version_pattern = re.compile(r"\d+\.\d+")
    for h in version_headers:
        val = headers.get(h, "")
        if val and version_pattern.search(val):
            disclosures.append(f"{h}: {val}")
    return disclosures


def _check_cookies(resp) -> list:
    cookie_issues = []
    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("missing HttpOnly flag")
        if issues:
            cookie_issues.append({
                "name": cookie.name,
                "issues": issues,
            })
    return cookie_issues
