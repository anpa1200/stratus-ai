"""
Unit tests for the port scanner's XML parser.
"""
import pytest
from assessment.scanners.external.port_scan import _parse_nmap_xml


NMAP_SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --open -T4 -p 22,80,443 example.com" start="1700000000">
<host starttime="1700000001" endtime="1700000010">
<status state="up" reason="echo-reply"/>
<address addr="93.184.216.34" addrtype="ipv4"/>
<ports>
  <port protocol="tcp" portid="22">
    <state state="open" reason="syn-ack"/>
    <service name="ssh" product="OpenSSH" version="8.9"/>
  </port>
  <port protocol="tcp" portid="80">
    <state state="open" reason="syn-ack"/>
    <service name="http" product="nginx" version="1.24.0"/>
  </port>
  <port protocol="tcp" portid="443">
    <state state="open" reason="syn-ack"/>
    <service name="https" product="nginx"/>
  </port>
  <port protocol="tcp" portid="8080">
    <state state="closed" reason="reset"/>
    <service name="http-proxy"/>
  </port>
</ports>
</host>
</nmaprun>"""

NMAP_EMPTY_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
<host starttime="1700000001" endtime="1700000010">
<status state="up"/>
<ports>
</ports>
</host>
</nmaprun>"""

NMAP_NO_HOST_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
</nmaprun>"""


class TestParseNmapXML:
    def test_parses_open_ports(self):
        ports = _parse_nmap_xml(NMAP_SAMPLE_XML)
        assert len(ports) == 3  # 22, 80, 443 (not 8080 which is closed)

    def test_port_numbers_correct(self):
        ports = _parse_nmap_xml(NMAP_SAMPLE_XML)
        port_nums = [p["port"] for p in ports]
        assert 22 in port_nums
        assert 80 in port_nums
        assert 443 in port_nums
        assert 8080 not in port_nums  # closed

    def test_service_names_extracted(self):
        ports = _parse_nmap_xml(NMAP_SAMPLE_XML)
        port_map = {p["port"]: p for p in ports}
        assert port_map[22]["service"] == "ssh"
        assert port_map[22]["product"] == "OpenSSH"
        assert port_map[22]["version"] == "8.9"
        assert port_map[80]["service"] == "http"

    def test_protocol_extracted(self):
        ports = _parse_nmap_xml(NMAP_SAMPLE_XML)
        for p in ports:
            assert p["protocol"] == "tcp"

    def test_empty_ports_returns_empty_list(self):
        ports = _parse_nmap_xml(NMAP_EMPTY_XML)
        assert ports == []

    def test_no_host_returns_empty_list(self):
        ports = _parse_nmap_xml(NMAP_NO_HOST_XML)
        assert ports == []

    def test_invalid_xml_returns_empty_list(self):
        ports = _parse_nmap_xml("this is not xml")
        assert ports == []

    def test_empty_string_returns_empty_list(self):
        ports = _parse_nmap_xml("")
        assert ports == []

    def test_service_missing_product_version(self):
        xml = """<?xml version="1.0"?>
<nmaprun>
<host>
<ports>
  <port protocol="tcp" portid="3306">
    <state state="open" reason="syn-ack"/>
    <service name="mysql"/>
  </port>
</ports>
</host>
</nmaprun>"""
        ports = _parse_nmap_xml(xml)
        assert len(ports) == 1
        assert ports[0]["port"] == 3306
        assert ports[0]["service"] == "mysql"
        assert ports[0]["product"] == ""
        assert ports[0]["version"] == ""

    def test_no_service_element(self):
        xml = """<?xml version="1.0"?>
<nmaprun>
<host>
<ports>
  <port protocol="tcp" portid="12345">
    <state state="open" reason="syn-ack"/>
  </port>
</ports>
</host>
</nmaprun>"""
        ports = _parse_nmap_xml(xml)
        assert len(ports) == 1
        assert ports[0]["port"] == 12345
        assert ports[0]["service"] == ""
