from assessment.scanners.aws.iam import IAMScanner
from assessment.scanners.aws.s3 import S3Scanner
from assessment.scanners.aws.ec2 import EC2Scanner
from assessment.scanners.aws.cloudtrail import CloudTrailScanner
from assessment.scanners.aws.rds import RDSScanner

AWS_SCANNERS = {
    "iam": IAMScanner,
    "s3": S3Scanner,
    "ec2": EC2Scanner,
    "cloudtrail": CloudTrailScanner,
    "rds": RDSScanner,
}
