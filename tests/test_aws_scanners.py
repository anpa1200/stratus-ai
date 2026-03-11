"""
Tests for AWS scanner modules using moto (mocked AWS services).
Run with: pytest tests/test_aws_scanners.py -v

Requires: moto[iam,s3,ec2,lambda,kms,secretsmanager]
Install with: pip install "moto[iam,s3,ec2,lambda,kms,secretsmanager]>=5.0"
"""
import json
import pytest

try:
    import boto3
    import moto
    from moto import mock_aws
    MOTO_AVAILABLE = True
except ImportError:
    MOTO_AVAILABLE = False

pytestmark = pytest.mark.skipif(not MOTO_AVAILABLE, reason="moto not installed")


# ─── IAM Scanner ─────────────────────────────────────────────────────────────

@mock_aws
def test_iam_scans_empty_account():
    session = boto3.Session(region_name="us-east-1")
    from assessment.scanners.aws.iam import IAMScanner
    scanner = IAMScanner(session=session, region="us-east-1")
    result = scanner.scan()
    assert result.error is None
    assert "users" in result.raw_output
    assert result.raw_output["users"] == []


@mock_aws
def test_iam_detects_user_without_mfa():
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.create_user(UserName="testuser")

    from assessment.scanners.aws.iam import IAMScanner
    result = IAMScanner(session=session, region="us-east-1").scan()
    assert result.error is None
    users = result.raw_output["users"]
    assert len(users) == 1
    assert users[0]["username"] == "testuser"
    assert users[0]["mfa_enabled"] is False


@mock_aws
def test_iam_detects_password_policy():
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    iam.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireUppercaseCharacters=True,
        RequireNumbers=True,
        RequireSymbols=True,
    )
    from assessment.scanners.aws.iam import IAMScanner
    result = IAMScanner(session=session, region="us-east-1").scan()
    policy = result.raw_output["password_policy"]
    assert policy["minimum_password_length"] == 14
    assert policy["require_uppercase"] is True


@mock_aws
def test_iam_handles_no_password_policy():
    session = boto3.Session(region_name="us-east-1")
    from assessment.scanners.aws.iam import IAMScanner
    result = IAMScanner(session=session, region="us-east-1").scan()
    policy = result.raw_output["password_policy"]
    assert policy.get("configured") is False or "note" in policy


@mock_aws
def test_iam_detects_admin_policy_attachment():
    import json
    from unittest.mock import patch
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    # moto doesn't pre-populate AWS managed policies — create a customer-managed one
    resp = iam.create_policy(
        PolicyName="AdministratorAccess",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }),
    )
    policy_arn = resp["Policy"]["Arn"]
    iam.create_user(UserName="adminuser")
    iam.attach_user_policy(UserName="adminuser", PolicyArn=policy_arn)
    # Patch the config constant so the scanner looks for our test policy ARN
    with patch("assessment.scanners.aws.iam.OVERPRIVILEGED_MANAGED_POLICIES", [policy_arn]):
        from assessment.scanners.aws.iam import IAMScanner
        result = IAMScanner(session=session, region="us-east-1").scan()
    admin_attachments = result.raw_output["attached_admin_policies"]
    assert any(a["name"] == "adminuser" for a in admin_attachments)


@mock_aws
def test_iam_multiple_users():
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    for name in ["alice", "bob", "charlie"]:
        iam.create_user(UserName=name)
    from assessment.scanners.aws.iam import IAMScanner
    result = IAMScanner(session=session, region="us-east-1").scan()
    assert len(result.raw_output["users"]) == 3


# ─── S3 Scanner ──────────────────────────────────────────────────────────────

@mock_aws
def test_s3_scans_empty_account():
    session = boto3.Session(region_name="us-east-1")
    from assessment.scanners.aws.s3 import S3Scanner
    result = S3Scanner(session=session, region="us-east-1").scan()
    assert result.error is None
    assert result.raw_output["buckets"] == []


@mock_aws
def test_s3_lists_buckets():
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket-1")
    s3.create_bucket(Bucket="test-bucket-2")
    from assessment.scanners.aws.s3 import S3Scanner
    result = S3Scanner(session=session, region="us-east-1").scan()
    assert len(result.raw_output["buckets"]) == 2


@mock_aws
def test_s3_detects_encryption_disabled():
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="unencrypted-bucket")
    from assessment.scanners.aws.s3 import S3Scanner
    result = S3Scanner(session=session, region="us-east-1").scan()
    bucket = result.raw_output["buckets"][0]
    assert bucket["encryption"] == "none"


@mock_aws
def test_s3_detects_versioning_disabled():
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="unversioned-bucket")
    from assessment.scanners.aws.s3 import S3Scanner
    result = S3Scanner(session=session, region="us-east-1").scan()
    bucket = result.raw_output["buckets"][0]
    assert bucket["versioning"] in ("Disabled", "", None)


@mock_aws
def test_s3_detects_versioning_enabled():
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="versioned-bucket")
    s3.put_bucket_versioning(
        Bucket="versioned-bucket",
        VersioningConfiguration={"Status": "Enabled"},
    )
    from assessment.scanners.aws.s3 import S3Scanner
    result = S3Scanner(session=session, region="us-east-1").scan()
    bucket = result.raw_output["buckets"][0]
    assert bucket["versioning"] == "Enabled"


@mock_aws
def test_s3_detects_public_bucket_policy():
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="public-policy-bucket")
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::public-policy-bucket/*",
        }]
    })
    s3.put_bucket_policy(Bucket="public-policy-bucket", Policy=policy)
    from assessment.scanners.aws.s3 import S3Scanner
    result = S3Scanner(session=session, region="us-east-1").scan()
    bucket = result.raw_output["buckets"][0]
    assert bucket["policy_allows_public"] is True


# ─── EC2 Scanner ─────────────────────────────────────────────────────────────

@mock_aws
def test_ec2_scans_empty_region():
    session = boto3.Session(region_name="us-east-1")
    from assessment.scanners.aws.ec2 import EC2Scanner
    result = EC2Scanner(session=session, region="us-east-1").scan()
    assert result.error is None
    assert "security_groups" in result.raw_output
    assert "instances" in result.raw_output


@mock_aws
def test_ec2_detects_open_security_group():
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="open-sg", Description="Wide open SG")
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )
    from assessment.scanners.aws.ec2 import EC2Scanner
    result = EC2Scanner(session=session, region="us-east-1").scan()
    open_sgs = [sg for sg in result.raw_output["security_groups"] if sg["group_id"] == sg_id]
    assert len(open_sgs) == 1
    assert open_sgs[0]["inbound_open_to_world"]


@mock_aws
def test_ec2_detects_sensitive_port_in_sg():
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="rdp-sg", Description="RDP open")
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )
    from assessment.scanners.aws.ec2 import EC2Scanner
    result = EC2Scanner(session=session, region="us-east-1").scan()
    sg_result = next(sg for sg in result.raw_output["security_groups"] if sg["group_id"] == sg_id)
    assert any("RDP" in p for p in sg_result["inbound_sensitive_ports_open"])


@mock_aws
def test_ec2_ebs_encryption_default_checked():
    session = boto3.Session(region_name="us-east-1")
    from assessment.scanners.aws.ec2 import EC2Scanner
    result = EC2Scanner(session=session, region="us-east-1").scan()
    assert "ebs_encryption_default" in result.raw_output
    assert "enabled" in result.raw_output["ebs_encryption_default"]


# ─── Lambda Scanner ───────────────────────────────────────────────────────────

@mock_aws
def test_lambda_scans_empty_region():
    session = boto3.Session(region_name="us-east-1")
    from assessment.scanners.aws.lambda_scan import LambdaScanner
    result = LambdaScanner(session=session, region="us-east-1").scan()
    assert result.error is None
    assert result.raw_output["functions"] == []


@mock_aws
def test_lambda_detects_function():
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
    })
    role_arn = iam.create_role(RoleName="lambda-role", AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    lmb = session.client("lambda", region_name="us-east-1")
    lmb.create_function(
        FunctionName="my-function",
        Runtime="python3.11",
        Role=role_arn,
        Handler="handler.main",
        Code={"ZipFile": b"def handler(e,c): pass"},
    )
    from assessment.scanners.aws.lambda_scan import LambdaScanner
    result = LambdaScanner(session=session, region="us-east-1").scan()
    assert len(result.raw_output["functions"]) == 1
    assert result.raw_output["functions"][0]["name"] == "my-function"


@mock_aws
def test_lambda_detects_deprecated_runtime():
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
    })
    role_arn = iam.create_role(RoleName="lambda-role2", AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    lmb = session.client("lambda", region_name="us-east-1")
    lmb.create_function(
        FunctionName="old-function",
        Runtime="python3.6",
        Role=role_arn,
        Handler="handler.main",
        Code={"ZipFile": b"def handler(e,c): pass"},
    )
    from assessment.scanners.aws.lambda_scan import LambdaScanner
    result = LambdaScanner(session=session, region="us-east-1").scan()
    fn = result.raw_output["functions"][0]
    assert fn["deprecated_runtime"] is True


@mock_aws
def test_lambda_detects_suspicious_env_vars():
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
    })
    role_arn = iam.create_role(RoleName="lambda-role3", AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    lmb = session.client("lambda", region_name="us-east-1")
    lmb.create_function(
        FunctionName="secret-function",
        Runtime="python3.11",
        Role=role_arn,
        Handler="handler.main",
        Code={"ZipFile": b"def handler(e,c): pass"},
        Environment={"Variables": {"DB_PASSWORD": "hunter2", "API_TOKEN": "abc123"}},
    )
    from assessment.scanners.aws.lambda_scan import LambdaScanner
    result = LambdaScanner(session=session, region="us-east-1").scan()
    fn = result.raw_output["functions"][0]
    assert fn["has_suspicious_env_vars"] is True
    assert "DB_PASSWORD" in fn["suspicious_env_vars"] or "API_TOKEN" in fn["suspicious_env_vars"]


# ─── KMS Scanner ─────────────────────────────────────────────────────────────

@mock_aws
def test_kms_scans_no_customer_keys():
    session = boto3.Session(region_name="us-east-1")
    from assessment.scanners.aws.kms import KMSScanner
    result = KMSScanner(session=session, region="us-east-1").scan()
    assert result.error is None
    assert isinstance(result.raw_output["keys"], list)


@mock_aws
def test_kms_detects_customer_key():
    session = boto3.Session(region_name="us-east-1")
    kms = session.client("kms", region_name="us-east-1")
    key = kms.create_key(Description="Test CMK", KeyUsage="ENCRYPT_DECRYPT")
    key_id = key["KeyMetadata"]["KeyId"]
    from assessment.scanners.aws.kms import KMSScanner
    result = KMSScanner(session=session, region="us-east-1").scan()
    keys = result.raw_output["keys"]
    assert len(keys) >= 1
    assert any(k["key_id"] == key_id for k in keys)


@mock_aws
def test_kms_rotation_status_checked():
    session = boto3.Session(region_name="us-east-1")
    kms = session.client("kms", region_name="us-east-1")
    key = kms.create_key(Description="Test CMK", KeyUsage="ENCRYPT_DECRYPT")
    key_id = key["KeyMetadata"]["KeyId"]
    from assessment.scanners.aws.kms import KMSScanner
    result = KMSScanner(session=session, region="us-east-1").scan()
    key_result = next(k for k in result.raw_output["keys"] if k["key_id"] == key_id)
    assert "rotation_enabled" in key_result


# ─── Secrets Manager Scanner ──────────────────────────────────────────────────

@mock_aws
def test_secretsmanager_scans_empty_account():
    session = boto3.Session(region_name="us-east-1")
    from assessment.scanners.aws.secrets_manager import SecretsManagerScanner
    result = SecretsManagerScanner(session=session, region="us-east-1").scan()
    assert result.error is None
    assert result.raw_output["secrets"] == []


@mock_aws
def test_secretsmanager_detects_secret():
    session = boto3.Session(region_name="us-east-1")
    sm = session.client("secretsmanager", region_name="us-east-1")
    sm.create_secret(Name="prod/db/password", SecretString="hunter2")
    from assessment.scanners.aws.secrets_manager import SecretsManagerScanner
    result = SecretsManagerScanner(session=session, region="us-east-1").scan()
    assert len(result.raw_output["secrets"]) == 1
    assert result.raw_output["secrets"][0]["name"] == "prod/db/password"


@mock_aws
def test_secretsmanager_detects_rotation_disabled():
    session = boto3.Session(region_name="us-east-1")
    sm = session.client("secretsmanager", region_name="us-east-1")
    sm.create_secret(Name="no-rotation-secret", SecretString="value")
    from assessment.scanners.aws.secrets_manager import SecretsManagerScanner
    result = SecretsManagerScanner(session=session, region="us-east-1").scan()
    secret = result.raw_output["secrets"][0]
    assert secret["rotation_enabled"] is False


@mock_aws
def test_secretsmanager_detects_default_kms():
    session = boto3.Session(region_name="us-east-1")
    sm = session.client("secretsmanager", region_name="us-east-1")
    sm.create_secret(Name="default-kms-secret", SecretString="value")
    from assessment.scanners.aws.secrets_manager import SecretsManagerScanner
    result = SecretsManagerScanner(session=session, region="us-east-1").scan()
    secret = result.raw_output["secrets"][0]
    assert secret["uses_default_kms"] is True
