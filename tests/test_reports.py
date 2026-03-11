"""
Unit tests for HTML and Markdown report generators.
No API calls required — pure unit tests against fixture data.
"""
import pytest
from datetime import datetime, timezone
from assessment.models import Report, Finding, ModuleResult, AttackChain
from assessment.reports.html import generate_html, _esc
from assessment.reports.markdown import generate_markdown


def _make_report(**kwargs) -> Report:
    """Create a minimal but valid Report for testing."""
    findings = kwargs.pop("findings", [
        Finding("f1", "Root MFA Disabled", "CRITICAL", "iam",
                "Root account has no MFA enabled.", "mfa_active: false",
                "aws iam enable-mfa-device ...", resource="arn:aws:iam::123:root",
                provider="aws"),
        Finding("f2", "S3 Bucket Public Read", "HIGH", "s3",
                "Bucket allows public read access.", "acl_public_read: true",
                "aws s3api put-public-access-block ...", resource="my-data-bucket",
                provider="aws"),
        Finding("f3", "EBS Volume Unencrypted", "MEDIUM", "ec2",
                "Attached EBS volume is not encrypted.", "vol-abc: encrypted=false",
                "Encrypt volume or enable default encryption", provider="aws"),
    ])

    module_results = kwargs.pop("module_results", [
        ModuleResult("iam", "aws", {}, findings[:1], module_risk_score=80,
                     module_summary="IAM has critical issues.", duration_seconds=1.2,
                     input_tokens=5000, output_tokens=800),
        ModuleResult("s3", "aws", {}, findings[1:2], module_risk_score=60,
                     module_summary="S3 has public buckets.", duration_seconds=2.1,
                     input_tokens=4000, output_tokens=600),
    ])

    return Report(
        scan_id="abc12345",
        timestamp=datetime(2025, 3, 11, 12, 0, 0, tzinfo=timezone.utc),
        provider="aws",
        account_id="123456789012",
        regions=["us-east-1"],
        mode="both",
        module_results=module_results,
        findings=findings,
        attack_chains=[
            AttackChain(
                title="SSRF to Credential Theft",
                steps=["Exploit SSRF", "Access IMDSv1", "Steal credentials", "Pivot"],
                findings_involved=["f1", "f2"],
                likelihood="HIGH",
                impact="CRITICAL",
            )
        ],
        top_10_priorities=["f1", "f2", "f3"],
        recommended_immediate_actions=[
            "Enable MFA on root account immediately",
            "Block public access on S3 bucket my-data-bucket",
        ],
        overall_risk_rating="HIGH",
        overall_risk_score=72,
        executive_summary="This account has critical security issues requiring immediate attention.",
        total_input_tokens=9000,
        total_output_tokens=1400,
        estimated_cost_usd=0.048,
        model_used="claude-sonnet-4-6",
        **kwargs,
    )


# ─── HTML generator tests ─────────────────────────────────────────────────────

class TestGenerateHTML:
    def test_returns_string(self):
        report = _make_report()
        html = generate_html(report)
        assert isinstance(html, str)
        assert len(html) > 1000

    def test_contains_doctype(self):
        html = generate_html(_make_report())
        assert "<!DOCTYPE html>" in html

    def test_contains_account_id(self):
        html = generate_html(_make_report())
        assert "123456789012" in html

    def test_contains_risk_rating(self):
        html = generate_html(_make_report())
        assert "HIGH" in html
        assert "72/100" in html

    def test_contains_findings(self):
        html = generate_html(_make_report())
        assert "Root MFA Disabled" in html
        assert "S3 Bucket Public Read" in html

    def test_contains_attack_chains(self):
        html = generate_html(_make_report())
        assert "SSRF to Credential Theft" in html

    def test_contains_immediate_actions(self):
        html = generate_html(_make_report())
        assert "Enable MFA on root account" in html

    def test_contains_cost_info(self):
        html = generate_html(_make_report())
        assert "claude-sonnet-4-6" in html
        assert "0.0480" in html  # cost display

    def test_contains_token_counts(self):
        html = generate_html(_make_report())
        assert "9,000" in html  # formatted input tokens
        assert "1,400" in html  # formatted output tokens

    def test_severity_classes_present(self):
        html = generate_html(_make_report())
        assert "sev-CRITICAL" in html
        assert "sev-HIGH" in html
        assert "sev-MEDIUM" in html

    def test_filter_buttons_present(self):
        html = generate_html(_make_report())
        assert "filterFindings" in html or "setFilter" in html

    def test_module_sections_present(self):
        html = generate_html(_make_report())
        assert "AWS/iam" in html.upper() or "iam" in html

    def test_xss_escape_in_account_id(self):
        report = _make_report()
        report.account_id = '<script>alert("xss")</script>'
        html = generate_html(report)
        assert 'alert("xss")' not in html
        assert "&lt;script&gt;" in html

    def test_empty_findings(self):
        report = _make_report(findings=[], module_results=[])
        html = generate_html(report)
        assert isinstance(html, str)
        assert "No findings" in html

    def test_no_attack_chains_section_hidden(self):
        report = _make_report()
        report.attack_chains = []
        html = generate_html(report)
        assert "Attack Chains" not in html

    def test_top10_section_present(self):
        html = generate_html(_make_report())
        assert "Top 10" in html

    def test_executive_summary_present(self):
        html = generate_html(_make_report())
        assert "critical security issues" in html


# ─── Markdown generator tests ─────────────────────────────────────────────────

class TestGenerateMarkdown:
    def test_returns_string(self):
        md = generate_markdown(_make_report())
        assert isinstance(md, str)

    def test_contains_report_header(self):
        md = generate_markdown(_make_report())
        assert "# Cloud Security Assessment" in md

    def test_contains_scan_metadata(self):
        md = generate_markdown(_make_report())
        assert "123456789012" in md
        assert "abc12345" in md
        assert "us-east-1" in md

    def test_contains_risk_rating(self):
        md = generate_markdown(_make_report())
        assert "HIGH" in md
        assert "72" in md

    def test_contains_finding_table(self):
        md = generate_markdown(_make_report())
        assert "Root MFA Disabled" in md
        assert "S3 Bucket Public Read" in md

    def test_contains_attack_chains(self):
        md = generate_markdown(_make_report())
        assert "SSRF to Credential Theft" in md

    def test_contains_immediate_actions(self):
        md = generate_markdown(_make_report())
        assert "Enable MFA on root account" in md

    def test_contains_executive_summary(self):
        md = generate_markdown(_make_report())
        assert "critical security issues" in md

    def test_contains_top10(self):
        md = generate_markdown(_make_report())
        assert "Top 10" in md

    def test_contains_module_sections(self):
        md = generate_markdown(_make_report())
        assert "IAM" in md.upper()

    def test_contains_cost_info(self):
        md = generate_markdown(_make_report())
        assert "claude-sonnet-4-6" in md
        assert "0.0480" in md

    def test_severity_emojis_present(self):
        md = generate_markdown(_make_report())
        # Check for emoji characters
        assert any(emoji in md for emoji in ["🔴", "🟠", "🟡", "🔵"])

    def test_empty_findings_handled(self):
        report = _make_report(findings=[], module_results=[])
        md = generate_markdown(report)
        assert isinstance(md, str)


# ─── HTML escape tests ────────────────────────────────────────────────────────

class TestEscapeFunction:
    def test_escapes_angle_brackets(self):
        assert _esc("<script>") == "&lt;script&gt;"

    def test_escapes_ampersand(self):
        assert _esc("foo & bar") == "foo &amp; bar"

    def test_escapes_quotes(self):
        assert _esc('"quoted"') == "&quot;quoted&quot;"

    def test_none_returns_empty(self):
        assert _esc(None) == ""

    def test_empty_string(self):
        assert _esc("") == ""

    def test_plain_text_unchanged(self):
        assert _esc("hello world") == "hello world"

    def test_number_converted(self):
        assert _esc(42) == "42"
