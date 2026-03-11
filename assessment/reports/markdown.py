"""
Markdown report generator.
"""
from assessment.models import Report

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}


def generate_markdown(report: Report) -> str:
    lines = []

    lines.append(f"# Cloud Security Assessment Report")
    lines.append(f"")
    lines.append(f"**Scan ID:** `{report.scan_id}`  ")
    lines.append(f"**Timestamp:** {report.timestamp.isoformat()}  ")
    lines.append(f"**Provider:** {report.provider.upper()}  ")
    lines.append(f"**Account:** {report.account_id}  ")
    lines.append(f"**Regions:** {', '.join(report.regions)}  ")
    lines.append(f"**Mode:** {report.mode}  ")
    lines.append(f"")

    # Risk badge
    risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(report.overall_risk_rating, "⚪")
    lines.append(f"## {risk_emoji} Overall Risk: {report.overall_risk_rating} ({report.overall_risk_score}/100)")
    lines.append(f"")

    # Finding counts
    counts = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    for f in report.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    lines.append(f"| CRITICAL | HIGH | MEDIUM | LOW | INFO |")
    lines.append(f"|----------|------|--------|-----|------|")
    lines.append(f"| {counts['CRITICAL']} | {counts['HIGH']} | {counts['MEDIUM']} | {counts['LOW']} | {counts['INFO']} |")
    lines.append(f"")

    # Executive summary
    lines.append(f"## Executive Summary")
    lines.append(f"")
    lines.append(report.executive_summary)
    lines.append(f"")

    # Immediate actions
    if report.recommended_immediate_actions:
        lines.append(f"## Immediate Actions")
        lines.append(f"")
        for action in report.recommended_immediate_actions:
            lines.append(f"1. {action}")
        lines.append(f"")

    # Attack chains
    if report.attack_chains:
        lines.append(f"## Attack Chains")
        lines.append(f"")
        for chain in report.attack_chains:
            lines.append(f"### {chain.title}")
            lines.append(f"**Likelihood:** {chain.likelihood} | **Impact:** {chain.impact}")
            lines.append(f"")
            for i, step in enumerate(chain.steps, 1):
                lines.append(f"{i}. {step}")
            lines.append(f"")
            lines.append(f"*Findings involved: {', '.join(chain.findings_involved)}*")
            lines.append(f"")

    # Top 10 priorities
    if report.top_10_priorities:
        lines.append(f"## Top 10 Priorities")
        lines.append(f"")
        finding_map = {f.id: f for f in report.findings}
        for i, fid in enumerate(report.top_10_priorities[:10], 1):
            f = finding_map.get(fid)
            if f:
                lines.append(f"{i}. **[{f.severity}]** {f.title} — `{f.resource or f.category}`")
            else:
                lines.append(f"{i}. `{fid}`")
        lines.append(f"")

    # All findings by module
    lines.append(f"## Findings by Module")
    lines.append(f"")

    modules_seen = {}
    for f in report.findings:
        modules_seen.setdefault(f.category, []).append(f)

    for module, findings in modules_seen.items():
        lines.append(f"### {module.upper()}")
        lines.append(f"")
        lines.append(f"| Severity | Title | Resource | Remediation |")
        lines.append(f"|----------|-------|----------|-------------|")
        for f in sorted(findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.severity)):
            emoji = SEVERITY_EMOJI.get(f.severity, "")
            resource = f.resource or "—"
            remediation = f.remediation[:80] + "..." if len(f.remediation) > 80 else f.remediation
            lines.append(f"| {emoji} {f.severity} | {f.title} | `{resource}` | {remediation} |")
        lines.append(f"")

        # Detail blocks
        for f in findings:
            lines.append(f"<details>")
            lines.append(f"<summary>{SEVERITY_EMOJI.get(f.severity,'')} {f.title}</summary>")
            lines.append(f"")
            lines.append(f"**Description:** {f.description}")
            lines.append(f"")
            lines.append(f"**Evidence:** `{f.evidence}`")
            lines.append(f"")
            lines.append(f"**Remediation:** `{f.remediation}`")
            lines.append(f"")
            lines.append(f"</details>")
            lines.append(f"")

    return "\n".join(lines)
