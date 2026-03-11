from assessment.scanners.external.port_scan import PortScanner
from assessment.scanners.external.ssl_scan import SSLScanner
from assessment.scanners.external.http_headers import HTTPHeadersScanner
from assessment.scanners.external.dns_scan import DNSScanner

EXTERNAL_SCANNERS = {
    "ports": PortScanner,
    "ssl": SSLScanner,
    "http_headers": HTTPHeadersScanner,
    "dns": DNSScanner,
}
