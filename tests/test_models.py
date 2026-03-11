"""
Unit tests for assessment/models.py — dataclass integrity.
"""
import pytest
from datetime import datetime, timezone
from assessment.models import Finding, ModuleResult, AttackChain, Report


class TestFinding:
    def test_finding_creation(self):
        f = Finding(
            id="test_finding",
            title="Test Finding",
            severity="HIGH",
            category="iam",
            description="A test finding",
            evidence="some evidence",
            remediation="fix this",
        )
        assert f.id == "test_finding"
        assert f.severity == "HIGH"
        assert f.references == []
        assert f.resource == ""
        assert f.provider == ""

    def test_finding_with_all_fields(self):
        f = Finding(
            id="f1",
            title="Root MFA Disabled",
            severity="CRITICAL",
            category="iam",
            description="Root account has no MFA.",
            evidence="mfa_active: false",
            remediation="aws iam enable-mfa-device ...",
            resource="arn:aws:iam::123:root",
            region="us-east-1",
            provider="aws",
            references=["https://example.com"],
        )
        assert f.region == "us-east-1"
        assert len(f.references) == 1


class TestModuleResult:
    def test_default_values(self):
        mr = ModuleResult(
            module_name="iam",
            provider="aws",
            raw_output={"test": "data"},
            findings=[],
        )
        assert mr.module_risk_score == 0
        assert mr.module_summary == ""
        assert mr.duration_seconds == 0.0
        assert mr.error is None
        assert mr.input_tokens == 0
        assert mr.output_tokens == 0

    def test_with_error(self):
        mr = ModuleResult(
            module_name="s3",
            provider="aws",
            raw_output={},
            findings=[],
            error="Connection refused",
        )
        assert mr.error == "Connection refused"


class TestAttackChain:
    def test_attack_chain(self):
        chain = AttackChain(
            title="Credential Theft via SSRF",
            steps=["Step 1", "Step 2", "Step 3"],
            findings_involved=["imds_v1_enabled", "overprivileged_role"],
            likelihood="HIGH",
            impact="CRITICAL",
        )
        assert len(chain.steps) == 3
        assert chain.impact == "CRITICAL"


class TestReport:
    def _make_report(self, **kwargs):
        defaults = {
            "scan_id": "abc123",
            "timestamp": datetime.now(timezone.utc),
            "provider": "aws",
            "account_id": "123456789012",
            "regions": ["us-east-1"],
            "mode": "both",
            "module_results": [],
            "findings": [],
            "attack_chains": [],
            "top_10_priorities": [],
            "recommended_immediate_actions": [],
        }
        defaults.update(kwargs)
        return Report(**defaults)

    def test_default_values(self):
        report = self._make_report()
        assert report.overall_risk_rating == "UNKNOWN"
        assert report.overall_risk_score == 0
        assert report.executive_summary == ""
        assert report.total_input_tokens == 0
        assert report.total_output_tokens == 0
        assert report.estimated_cost_usd == 0.0
        assert report.model_used == ""

    def test_with_token_tracking(self):
        report = self._make_report(
            total_input_tokens=50000,
            total_output_tokens=5000,
            estimated_cost_usd=0.225,
            model_used="claude-sonnet-4-6",
        )
        assert report.total_input_tokens == 50000
        assert report.estimated_cost_usd == 0.225
        assert report.model_used == "claude-sonnet-4-6"

    def test_findings_attached(self):
        findings = [
            Finding("f1", "Test", "HIGH", "iam", "desc", "evidence", "fix"),
            Finding("f2", "Test2", "CRITICAL", "s3", "desc2", "ev2", "fix2"),
        ]
        report = self._make_report(findings=findings, overall_risk_rating="CRITICAL", overall_risk_score=85)
        assert len(report.findings) == 2
        assert report.overall_risk_rating == "CRITICAL"
