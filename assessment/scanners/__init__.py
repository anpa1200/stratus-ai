from assessment.scanners.aws import AWS_SCANNERS
from assessment.scanners.external import EXTERNAL_SCANNERS
from assessment.scanners.gcp import GCP_SCANNERS
from assessment.scanners.azure import AZURE_SCANNERS

ALL_SCANNERS = {
    "aws": AWS_SCANNERS,
    "external": EXTERNAL_SCANNERS,
    "gcp": GCP_SCANNERS,
    "azure": AZURE_SCANNERS,
}
