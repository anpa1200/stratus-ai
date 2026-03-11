"""
Self-contained dark-theme HTML report generator.
"""
import json
from assessment.models import Report

SEVERITY_COLOR = {
    "CRITICAL": "#ff4444",
    "HIGH": "#ff8c00",
    "MEDIUM": "#ffd700",
    "LOW": "#4fc3f7",
    "INFO": "#9e9e9e",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def generate_html(report: Report) -> str:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in report.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    risk_color = {
        "CRITICAL": "#ff4444", "HIGH": "#ff8c00",
        "MEDIUM": "#ffd700", "LOW": "#4fc3f7"
    }.get(report.overall_risk_rating, "#9e9e9e")

    findings_json = json.dumps([
        {
            "id": f.id, "title": f.title, "severity": f.severity,
            "category": f.category, "resource": f.resource,
            "description": f.description, "evidence": f.evidence,
            "remediation": f.remediation,
        }
        for f in report.findings
    ])

    attack_chains_html = _render_attack_chains(report.attack_chains)
    findings_table_html = _render_findings_table(report.findings)
    module_sections_html = _render_module_sections(report.module_results)

    immediate_actions_html = ""
    if report.recommended_immediate_actions:
        items = "".join(f"<li>{a}</li>" for a in report.recommended_immediate_actions)
        immediate_actions_html = f"<section class='immediate-actions'><h2>⚡ Immediate Actions</h2><ol>{items}</ol></section>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cloud Security Assessment — {report.account_id}</title>
<style>
  :root {{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;--text-muted:#8b949e;}}
  *{{box-sizing:border-box;margin:0;padding:0;}}
  body{{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-size:14px;line-height:1.6;}}
  .container{{max-width:1200px;margin:0 auto;padding:24px;}}
  h1{{font-size:24px;margin-bottom:8px;}}
  h2{{font-size:18px;margin:24px 0 12px;border-bottom:1px solid var(--border);padding-bottom:8px;}}
  h3{{font-size:15px;margin:16px 0 8px;}}
  .meta{{color:var(--text-muted);font-size:13px;margin-bottom:24px;}}
  .risk-badge{{display:inline-block;padding:8px 20px;border-radius:8px;font-weight:700;font-size:20px;margin-bottom:16px;color:#fff;background:{risk_color};}}
  .score-bar{{height:8px;background:var(--surface);border-radius:4px;overflow:hidden;margin-bottom:24px;max-width:400px;}}
  .score-fill{{height:100%;background:{risk_color};width:{report.overall_risk_score}%;}}
  .counts{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px;}}
  .count-badge{{padding:6px 14px;border-radius:6px;font-weight:600;font-size:13px;}}
  .executive-summary{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:24px;white-space:pre-wrap;}}
  section{{margin-bottom:32px;}}
  .immediate-actions{{background:rgba(255,140,0,0.08);border:1px solid #ff8c00;border-radius:8px;padding:20px;}}
  .immediate-actions li{{margin:6px 0 6px 20px;}}
  .chain-card{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:12px;}}
  .chain-meta{{color:var(--text-muted);font-size:12px;margin-bottom:8px;}}
  .chain-steps{{counter-reset:steps;list-style:none;}}
  .chain-steps li{{counter-increment:steps;margin:6px 0;padding-left:28px;position:relative;}}
  .chain-steps li::before{{content:counter(steps);position:absolute;left:0;background:#30363d;border-radius:50%;width:20px;height:20px;text-align:center;font-size:11px;line-height:20px;}}
  .filter-bar{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;}}
  .filter-btn{{padding:4px 12px;border-radius:4px;border:1px solid var(--border);background:var(--surface);color:var(--text);cursor:pointer;font-size:12px;}}
  .filter-btn.active{{border-color:currentColor;}}
  table{{width:100%;border-collapse:collapse;font-size:13px;}}
  th{{text-align:left;padding:8px 12px;background:var(--surface);border-bottom:2px solid var(--border);color:var(--text-muted);font-weight:600;}}
  td{{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:top;}}
  tr:hover td{{background:var(--surface);}}
  .sev{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;color:#000;}}
  .sev-CRITICAL{{background:#ff4444;color:#fff;}}
  .sev-HIGH{{background:#ff8c00;}}
  .sev-MEDIUM{{background:#ffd700;}}
  .sev-LOW{{background:#4fc3f7;}}
  .sev-INFO{{background:#9e9e9e;color:#fff;}}
  .module-section summary{{cursor:pointer;padding:12px;background:var(--surface);border-radius:6px;font-weight:600;}}
  .module-section[open] summary{{border-radius:6px 6px 0 0;border-bottom:1px solid var(--border);}}
  .module-content{{border:1px solid var(--border);border-top:none;border-radius:0 0 6px 6px;padding:16px;}}
  .risk-score{{float:right;color:var(--text-muted);font-weight:normal;font-size:13px;}}
  code{{background:var(--surface);padding:1px 6px;border-radius:3px;font-family:monospace;font-size:12px;}}
  .hidden{{display:none;}}
</style>
</head>
<body>
<div class="container">
  <h1>☁️ Cloud Security Assessment Report</h1>
  <div class="meta">
    Account: <strong>{report.account_id}</strong> &nbsp;|&nbsp;
    Provider: <strong>{report.provider.upper()}</strong> &nbsp;|&nbsp;
    Mode: <strong>{report.mode}</strong> &nbsp;|&nbsp;
    Regions: <strong>{', '.join(report.regions)}</strong> &nbsp;|&nbsp;
    {report.timestamp.strftime('%Y-%m-%d %H:%M UTC')}
  </div>

  <div class="risk-badge">{report.overall_risk_rating} — {report.overall_risk_score}/100</div>
  <div class="score-bar"><div class="score-fill"></div></div>

  <div class="counts">
    {_count_badge('CRITICAL', counts['CRITICAL'])}
    {_count_badge('HIGH', counts['HIGH'])}
    {_count_badge('MEDIUM', counts['MEDIUM'])}
    {_count_badge('LOW', counts['LOW'])}
    {_count_badge('INFO', counts['INFO'])}
  </div>

  {immediate_actions_html}

  <section>
    <h2>Executive Summary</h2>
    <div class="executive-summary">{_esc(report.executive_summary)}</div>
  </section>

  {attack_chains_html}

  <section>
    <h2>All Findings</h2>
    <div class="filter-bar">
      <button class="filter-btn active" onclick="filterFindings('ALL')">All</button>
      <button class="filter-btn" onclick="filterFindings('CRITICAL')">Critical</button>
      <button class="filter-btn" onclick="filterFindings('HIGH')">High</button>
      <button class="filter-btn" onclick="filterFindings('MEDIUM')">Medium</button>
      <button class="filter-btn" onclick="filterFindings('LOW')">Low</button>
    </div>
    {findings_table_html}
  </section>

  {module_sections_html}
</div>

<script>
const findings = {findings_json};

function filterFindings(severity) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('tr[data-severity]').forEach(row => {{
    row.classList.toggle('hidden', severity !== 'ALL' && row.dataset.severity !== severity);
  }});
}}
</script>
</body>
</html>"""


def _count_badge(severity: str, count: int) -> str:
    color = SEVERITY_COLOR.get(severity, "#9e9e9e")
    text_color = "#000" if severity in ("MEDIUM", "LOW") else "#fff"
    return (
        f'<div class="count-badge" style="background:{color};color:{text_color}">'
        f'{count} {severity}</div>'
    )


def _render_attack_chains(chains) -> str:
    if not chains:
        return ""
    items = ""
    for chain in chains:
        steps = "".join(f"<li>{_esc(s)}</li>" for s in chain.steps)
        items += f"""
        <div class="chain-card">
          <h3>{_esc(chain.title)}</h3>
          <div class="chain-meta">Likelihood: <strong>{chain.likelihood}</strong> &nbsp;|&nbsp; Impact: <strong>{chain.impact}</strong> &nbsp;|&nbsp; Findings: {', '.join(f'<code>{f}</code>' for f in chain.findings_involved)}</div>
          <ol class="chain-steps">{steps}</ol>
        </div>"""
    return f"<section><h2>⛓ Attack Chains</h2>{items}</section>"


def _render_findings_table(findings) -> str:
    if not findings:
        return "<p>No findings.</p>"
    rows = ""
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.severity)):
        rows += f"""<tr data-severity="{f.severity}">
          <td><span class="sev sev-{f.severity}">{f.severity}</span></td>
          <td>{_esc(f.title)}</td>
          <td><code>{_esc(f.category)}</code></td>
          <td><code>{_esc(f.resource or '—')}</code></td>
          <td>{_esc(f.description)}</td>
          <td><code>{_esc(f.remediation[:120])}</code></td>
        </tr>"""
    return f"""<table>
      <thead><tr><th>Severity</th><th>Title</th><th>Module</th><th>Resource</th><th>Description</th><th>Remediation</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""


def _render_module_sections(module_results) -> str:
    if not module_results:
        return ""
    sections = "<h2>Module Details</h2>"
    for mr in module_results:
        finding_count = len(mr.findings)
        score_text = f"Risk score: {mr.module_risk_score}/100" if mr.module_risk_score else ""
        error_html = f"<p style='color:#ff4444'>Error: {_esc(mr.error)}</p>" if mr.error else ""
        summary_html = f"<p>{_esc(mr.module_summary)}</p>" if mr.module_summary else ""

        findings_html = ""
        if mr.findings:
            rows = ""
            for f in mr.findings:
                rows += f"""<tr>
                  <td><span class="sev sev-{f.severity}">{f.severity}</span></td>
                  <td>{_esc(f.title)}</td>
                  <td><code>{_esc(f.resource or '—')}</code></td>
                  <td>{_esc(f.evidence)}</td>
                  <td><code>{_esc(f.remediation[:100])}</code></td>
                </tr>"""
            findings_html = f"""<table>
              <thead><tr><th>Severity</th><th>Title</th><th>Resource</th><th>Evidence</th><th>Remediation</th></tr></thead>
              <tbody>{rows}</tbody>
            </table>"""

        sections += f"""
        <details class="module-section" style="margin-bottom:8px">
          <summary>
            {mr.provider.upper()}/{mr.module_name}
            <span class="risk-score">{finding_count} findings &nbsp;|&nbsp; {score_text} &nbsp;|&nbsp; {mr.duration_seconds:.1f}s</span>
          </summary>
          <div class="module-content">
            {error_html}{summary_html}{findings_html}
          </div>
        </details>"""

    return f"<section>{sections}</section>"


def _esc(s: str) -> str:
    """HTML-escape a string."""
    if not s:
        return ""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))
