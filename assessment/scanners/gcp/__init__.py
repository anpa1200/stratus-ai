from assessment.scanners.gcp.iam import GCPIAMScanner
from assessment.scanners.gcp.compute import GCPComputeScanner
from assessment.scanners.gcp.storage import GCPStorageScanner
from assessment.scanners.gcp.cloudfunctions import GCPCloudFunctionsScanner
from assessment.scanners.gcp.cloudrun import GCPCloudRunScanner
from assessment.scanners.gcp.secretmanager import GCPSecretManagerScanner
from assessment.scanners.gcp.logging_scan import GCPLoggingScanner
from assessment.scanners.gcp.session import GCPSession

GCP_SCANNERS = {
    "iam": GCPIAMScanner,
    "compute": GCPComputeScanner,
    "storage": GCPStorageScanner,
    "cloudfunctions": GCPCloudFunctionsScanner,
    "cloudrun": GCPCloudRunScanner,
    "secretmanager": GCPSecretManagerScanner,
    "logging": GCPLoggingScanner,
}
