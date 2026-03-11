"""
pytest configuration and shared fixtures.
"""
import pytest
from datetime import datetime, timezone
from assessment.models import Report, Finding, ModuleResult, AttackChain


@pytest.fixture
def sample_findings():
    return [
        Finding(
            id="root_mfa_disabled",
            title="Root Account MFA Not Enabled",
            severity="CRITICAL",
            category="iam",
            description="The root account has no MFA device enabled.",
            evidence="mfa_active: false, root account",
            remediation="aws iam enable-mfa-device --user-name root ...",
            resource="arn:aws:iam::123456789012:root",
            provider="aws",
        ),
        Finding(
            id="s3_public_read",
            title="S3 Bucket Public Read ACL",
            severity="HIGH",
            category="s3",
            description="Bucket my-public-bucket allows public read access via ACL.",
            evidence="acl_public_read: true, bucket: my-public-bucket",
            remediation="aws s3api put-public-access-block --bucket my-public-bucket ...",
            resource="my-public-bucket",
            provider="aws",
        ),
        Finding(
            id="imdsv1_enabled",
            title="IMDSv1 Enabled on EC2 Instance",
            severity="HIGH",
            category="ec2",
            description="Instance allows IMDSv1 requests, enabling SSRF credential theft.",
            evidence="HttpTokens: optional, instance: i-abc123",
            remediation="aws ec2 modify-instance-metadata-options --instance-id i-abc123 --http-tokens required",
            resource="i-abc123",
            provider="aws",
        ),
        Finding(
            id="cloudtrail_disabled",
            title="No CloudTrail Trails Configured",
            severity="HIGH",
            category="cloudtrail",
            description="No CloudTrail trails exist — API activity is not logged.",
            evidence="trail_count: 0",
            remediation="aws cloudtrail create-trail --name main --s3-bucket-name my-audit-bucket --is-multi-region-trail",
            provider="aws",
        ),
    ]


@pytest.fixture
def sample_module_results(sample_findings):
    return [
        ModuleResult(
            module_name="iam",
            provider="aws",
            raw_output={"users": [], "root_account": {"mfa_active": False}},
            findings=[sample_findings[0]],
            module_risk_score=90,
            module_summary="Root account has no MFA. Critical risk.",
            duration_seconds=1.5,
            input_tokens=5000,
            output_tokens=800,
        ),
        ModuleResult(
            module_name="s3",
            provider="aws",
            raw_output={"buckets": [{"name": "my-public-bucket", "acl_public_read": True}]},
            findings=[sample_findings[1]],
            module_risk_score=70,
            module_summary="One bucket is publicly readable.",
            duration_seconds=2.3,
            input_tokens=4000,
            output_tokens=600,
        ),
    ]


@pytest.fixture
def sample_report(sample_findings, sample_module_results):
    return Report(
        scan_id="test1234",
        timestamp=datetime(2025, 3, 11, 12, 0, 0, tzinfo=timezone.utc),
        provider="aws",
        account_id="123456789012",
        regions=["us-east-1"],
        mode="internal",
        module_results=sample_module_results,
        findings=sample_findings[:2],
        attack_chains=[
            AttackChain(
                title="Unauthenticated Data Exfiltration",
                steps=[
                    "Attacker discovers public S3 bucket via internet scanner",
                    "Downloads sensitive data without credentials",
                    "Finds hardcoded credentials in files",
                    "Uses credentials to escalate privileges",
                ],
                findings_involved=["s3_public_read", "root_mfa_disabled"],
                likelihood="HIGH",
                impact="CRITICAL",
            )
        ],
        top_10_priorities=["root_mfa_disabled", "s3_public_read"],
        recommended_immediate_actions=[
            "Enable MFA on root account via AWS Console > Security credentials",
            "Block public access: aws s3api put-public-access-block --bucket my-public-bucket "
            "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
            "BlockPublicPolicy=true,RestrictPublicBuckets=true",
        ],
        overall_risk_rating="CRITICAL",
        overall_risk_score=88,
        executive_summary=(
            "This AWS account has critical security vulnerabilities requiring immediate attention. "
            "The root account has no MFA protection, and a publicly accessible S3 bucket "
            "exposes sensitive data to the internet without authentication."
        ),
        total_input_tokens=9000,
        total_output_tokens=1400,
        estimated_cost_usd=0.048,
        model_used="claude-sonnet-4-6",
    )
