"""
External port scanner — nmap against public endpoints.
"""
import logging
import subprocess
import re
import shutil
from assessment.scanners.base import BaseScanner
from assessment.config import EXTERNAL_SCAN_PORTS

logger = logging.getLogger(__name__)


class PortScanner(BaseScanner):
    name = "ports"
    provider = "external"

    def _scan(self) -> tuple[dict, list]:
        result = {
            "target": self.target,
            "nmap_result": _run_nmap(self.target),
        }
        return result, []


def _run_nmap(target: str) -> dict:
    if not shutil.which("nmap"):
        return {"error": "nmap not found"}
    try:
        cmd = [
            "nmap", "-sV", "--open", "-T4",
            "-p", EXTERNAL_SCAN_PORTS,
            "--host-timeout", "120s",
            "-oX", "-",  # XML output to stdout
            target,
        ]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=180, text=True)
        return {
            "target": target,
            "xml": out,
            "open_ports": _parse_nmap_xml(out),
        }
    except subprocess.TimeoutExpired:
        return {"error": "nmap timeout", "target": target}
    except subprocess.CalledProcessError as e:
        return {"error": f"nmap exit {e.returncode}", "target": target}
    except Exception as e:
        return {"error": str(e), "target": target}


def _parse_nmap_xml(xml: str) -> list:
    ports = []
    try:
        for m in re.finditer(
            r'<port protocol="(\w+)" portid="(\d+)".*?'
            r'<state state="(\w+)".*?'
            r'(?:<service name="([^"]*)"[^>]*/?>)?',
            xml, re.DOTALL
        ):
            if m.group(3) == "open":
                ports.append({
                    "protocol": m.group(1),
                    "port": int(m.group(2)),
                    "service": m.group(4) or "",
                })
    except Exception:
        pass
    return ports
