"""
External port scanner — nmap against public endpoints.
"""
import logging
import subprocess
import shutil
import xml.etree.ElementTree as ET
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
            "open_ports": _parse_nmap_xml(out),
        }
    except subprocess.TimeoutExpired:
        return {"error": "nmap timeout", "target": target}
    except subprocess.CalledProcessError as e:
        return {"error": f"nmap exit {e.returncode}", "target": target}
    except Exception as e:
        return {"error": str(e), "target": target}


def _parse_nmap_xml(xml_text: str) -> list:
    """Parse nmap XML output using ElementTree (not regex)."""
    ports = []
    try:
        root = ET.fromstring(xml_text)
        for host in root.findall("host"):
            ports_elem = host.find("ports")
            if ports_elem is None:
                continue
            for port_elem in ports_elem.findall("port"):
                state = port_elem.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port_elem.find("service")
                ports.append({
                    "protocol": port_elem.get("protocol", ""),
                    "port": int(port_elem.get("portid", 0)),
                    "service": service.get("name", "") if service is not None else "",
                    "product": service.get("product", "") if service is not None else "",
                    "version": service.get("version", "") if service is not None else "",
                })
    except ET.ParseError as e:
        logger.warning(f"nmap XML parse error: {e}")
    return ports
