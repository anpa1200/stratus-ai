"""
Self-contained dark-theme HTML report generator.
Includes: severity filtering, live search, cost/token tracking, module timings, print styles.
"""
import json
from assessment.models import Report

SEVERITY_COLOR = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8c00",
    "MEDIUM":   "#ffd700",
    "LOW":      "#4fc3f7",
    "INFO":     "#9e9e9e",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def generate_html(report: Report) -> str:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in report.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    risk_color = {
        "CRITICAL": "#ff4444", "HIGH": "#ff8c00",
        "MEDIUM":   "#ffd700", "LOW":  "#4fc3f7",
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
        items = "".join(f"<li>{_esc(a)}</li>" for a in report.recommended_immediate_actions)
        immediate_actions_html = (
            "<section class='immediate-actions'>"
            "<h2>&#9889; Immediate Actions</h2>"
            f"<ol>{items}</ol></section>"
        )

    cost_html = ""
    if report.total_input_tokens or report.total_output_tokens:
        cost_html = f"""
  <div class="cost-bar">
    <span class="cost-item">&#129302; {_esc(report.model_used or 'claude')}</span>
    <span class="cost-item">&#8594; {report.total_input_tokens:,} input tokens</span>
    <span class="cost-item">&#8594; {report.total_output_tokens:,} output tokens</span>
    <span class="cost-item cost-highlight">Est. cost: ${report.estimated_cost_usd:.4f}</span>
  </div>"""

    top_10_html = _render_top10(report.top_10_priorities, report.findings)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cloud Security Assessment &mdash; {_esc(report.account_id)}</title>
<style>
  :root {{
    --bg:#0d1117;--surface:#161b22;--surface2:#21262d;
    --border:#30363d;--text:#e6edf3;--text-muted:#8b949e;
    --accent:#1f6feb;
  }}
  *{{box-sizing:border-box;margin:0;padding:0;}}
  body{{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:14px;line-height:1.6;}}
  .container{{max-width:1300px;margin:0 auto;padding:24px;}}
  h1{{font-size:22px;margin-bottom:6px;}}
  h2{{font-size:17px;margin:28px 0 12px;border-bottom:1px solid var(--border);padding-bottom:8px;color:#c9d1d9;}}
  h3{{font-size:14px;margin:12px 0 6px;color:#c9d1d9;}}
  .meta{{color:var(--text-muted);font-size:12px;margin-bottom:20px;display:flex;flex-wrap:wrap;gap:12px;align-items:center;}}
  .meta strong{{color:var(--text);}}
  .risk-badge{{display:inline-flex;align-items:center;gap:8px;padding:10px 22px;border-radius:8px;font-weight:700;font-size:22px;margin-bottom:12px;color:#fff;background:{risk_color};box-shadow:0 0 20px {risk_color}40;}}
  .score-bar{{height:6px;background:var(--surface2);border-radius:3px;overflow:hidden;margin-bottom:24px;max-width:360px;}}
  .score-fill{{height:100%;background:{risk_color};width:{report.overall_risk_score}%;}}
  .counts{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px;}}
  .count-badge{{padding:5px 14px;border-radius:20px;font-weight:700;font-size:13px;cursor:pointer;border:2px solid transparent;transition:border-color 0.2s;}}
  .count-badge:hover{{border-color:currentColor;}}
  .executive-summary{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:24px;white-space:pre-wrap;font-size:13px;line-height:1.7;}}
  section{{margin-bottom:32px;}}
  .immediate-actions{{background:rgba(255,140,0,0.06);border:1px solid rgba(255,140,0,0.4);border-radius:8px;padding:20px;}}
  .immediate-actions h2{{color:#ff8c00;border-color:rgba(255,140,0,0.3);}}
  .immediate-actions li{{margin:7px 0 7px 20px;}}
  .chain-card{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:12px;}}
  .chain-meta{{color:var(--text-muted);font-size:12px;margin-bottom:10px;display:flex;gap:16px;flex-wrap:wrap;}}
  .chain-badge{{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;}}
  .chain-steps{{list-style:none;counter-reset:steps;}}
  .chain-steps li{{counter-increment:steps;margin:6px 0;padding-left:32px;position:relative;font-size:13px;}}
  .chain-steps li::before{{content:counter(steps);position:absolute;left:0;background:var(--surface2);border-radius:50%;width:22px;height:22px;text-align:center;font-size:11px;line-height:22px;border:1px solid var(--border);}}
  .top10-list{{list-style:none;}}
  .top10-list li{{padding:8px 12px;border-bottom:1px solid var(--border);display:flex;gap:12px;align-items:flex-start;font-size:13px;}}
  .top10-list li:last-child{{border-bottom:none;}}
  .top10-num{{color:var(--text-muted);min-width:24px;font-weight:600;}}
  .search-bar{{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center;}}
  .search-input{{flex:1;min-width:200px;padding:6px 12px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:13px;outline:none;}}
  .search-input:focus{{border-color:var(--accent);}}
  .filter-bar{{display:flex;gap:6px;flex-wrap:wrap;}}
  .filter-btn{{padding:4px 12px;border-radius:20px;border:1px solid var(--border);background:var(--surface);color:var(--text-muted);cursor:pointer;font-size:12px;transition:all 0.15s;}}
  .filter-btn:hover{{background:var(--surface2);color:var(--text);}}
  .filter-btn.active{{background:var(--accent);border-color:var(--accent);color:#fff;}}
  table{{width:100%;border-collapse:collapse;font-size:12.5px;}}
  th{{text-align:left;padding:8px 10px;background:var(--surface);border-bottom:2px solid var(--border);color:var(--text-muted);font-weight:600;white-space:nowrap;}}
  td{{padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top;}}
  tr:hover td{{background:var(--surface);}}
  .sev{{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px;font-weight:700;}}
  .sev-CRITICAL{{background:#ff4444;color:#fff;}}
  .sev-HIGH{{background:#ff8c00;color:#000;}}
  .sev-MEDIUM{{background:#ffd700;color:#000;}}
  .sev-LOW{{background:#4fc3f7;color:#000;}}
  .sev-INFO{{background:#9e9e9e;color:#fff;}}
  .module-section{{margin-bottom:6px;border:1px solid var(--border);border-radius:8px;overflow:hidden;}}
  .module-section summary{{cursor:pointer;padding:12px 16px;background:var(--surface);font-weight:600;font-size:13px;display:flex;justify-content:space-between;align-items:center;user-select:none;}}
  .module-section summary:hover{{background:var(--surface2);}}
  .module-content{{padding:16px;background:var(--bg);}}
  .module-meta{{display:flex;gap:16px;flex-wrap:wrap;align-items:center;}}
  .risk-score-pill{{padding:2px 8px;border-radius:10px;font-size:11px;}}
  code{{background:var(--surface2);padding:1px 5px;border-radius:3px;font-family:"SF Mono",Consolas,monospace;font-size:11.5px;word-break:break-all;}}
  .hidden{{display:none;}}
  .no-results{{padding:20px;text-align:center;color:var(--text-muted);}}
  .cost-bar{{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:8px 14px;margin-bottom:20px;display:flex;gap:16px;flex-wrap:wrap;align-items:center;font-size:12px;color:var(--text-muted);}}
  .cost-item{{display:flex;align-items:center;gap:4px;}}
  .cost-highlight{{color:#4fc3f7;font-weight:600;}}
  @media print {{
    body{{background:#fff !important;color:#000 !important;}}
    :root{{--bg:#fff;--surface:#f6f8fa;--surface2:#eee;--border:#ddd;--text:#000;--text-muted:#666;}}
    .filter-bar,.search-bar,.cost-bar{{display:none !important;}}
    .hidden{{display:table-row !important;}}
  }}
</style>
</head>
<body>
<div class="container">
  <h1>&#9729; Cloud Security Assessment Report</h1>
  <div class="meta">
    <span>Account: <strong>{_esc(report.account_id)}</strong></span>
    <span>Provider: <strong>{_esc(report.provider.upper())}</strong></span>
    <span>Mode: <strong>{_esc(report.mode)}</strong></span>
    <span>Regions: <strong>{_esc(', '.join(report.regions))}</strong></span>
    <span>Scan ID: <strong>{_esc(report.scan_id)}</strong></span>
    <span>{report.timestamp.strftime('%Y-%m-%d %H:%M UTC')}</span>
  </div>

  <div class="risk-badge">{_esc(report.overall_risk_rating)} &mdash; {report.overall_risk_score}/100</div>
  <div class="score-bar"><div class="score-fill"></div></div>

  <div class="counts">
    {_count_badge('CRITICAL', counts['CRITICAL'])}
    {_count_badge('HIGH', counts['HIGH'])}
    {_count_badge('MEDIUM', counts['MEDIUM'])}
    {_count_badge('LOW', counts['LOW'])}
    {_count_badge('INFO', counts['INFO'])}
  </div>

  {cost_html}

  {immediate_actions_html}

  <section>
    <h2>Executive Summary</h2>
    <div class="executive-summary">{_esc(report.executive_summary)}</div>
  </section>

  {attack_chains_html}

  {top_10_html}

  <section>
    <h2>All Findings ({len(report.findings)})</h2>
    <div class="search-bar">
      <input class="search-input" type="text" id="searchInput" placeholder="Search by title, resource, description..." oninput="applyFilters()">
      <div class="filter-bar">
        <button class="filter-btn active" onclick="setFilter('ALL',this)">All</button>
        <button class="filter-btn" onclick="setFilter('CRITICAL',this)">Critical</button>
        <button class="filter-btn" onclick="setFilter('HIGH',this)">High</button>
        <button class="filter-btn" onclick="setFilter('MEDIUM',this)">Medium</button>
        <button class="filter-btn" onclick="setFilter('LOW',this)">Low</button>
        <button class="filter-btn" onclick="setFilter('INFO',this)">Info</button>
      </div>
    </div>
    {findings_table_html}
  </section>

  {module_sections_html}
</div>

<script>
const findings = {findings_json};
let currentFilter = 'ALL';

function setFilter(severity, btn) {{
  currentFilter = severity;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  applyFilters();
}}

function applyFilters() {{
  const q = document.getElementById('searchInput').value.toLowerCase();
  let visible = 0;
  document.querySelectorAll('tr[data-severity]').forEach(row => {{
    const severityMatch = currentFilter === 'ALL' || row.dataset.severity === currentFilter;
    const textMatch = !q || row.textContent.toLowerCase().includes(q);
    const show = severityMatch && textMatch;
    row.classList.toggle('hidden', !show);
    if (show) visible++;
  }});
  const noResults = document.getElementById('noResults');
  if (noResults) noResults.classList.toggle('hidden', visible > 0);
}}
</script>
</body>
</html>"""


def _count_badge(severity: str, count: int) -> str:
    color = SEVERITY_COLOR.get(severity, "#9e9e9e")
    text_color = "#000" if severity in ("MEDIUM", "LOW") else "#fff"
    return (
        f'<div class="count-badge" style="background:{color};color:{text_color}" '
        f'onclick="setFilter(\'{severity}\',this)">'
        f'{count} {severity}</div>'
    )


def _render_attack_chains(chains) -> str:
    if not chains:
        return ""
    items = ""
    for chain in chains:
        steps = "".join(f"<li>{_esc(s)}</li>" for s in chain.steps)
        likelihood_color = {"HIGH": "#ff4444", "MEDIUM": "#ff8c00", "LOW": "#4fc3f7"}.get(chain.likelihood, "#9e9e9e")
        impact_color = {"HIGH": "#ff4444", "MEDIUM": "#ff8c00", "LOW": "#4fc3f7"}.get(chain.impact, "#9e9e9e")
        findings_html = " ".join(f'<code>{_esc(f)}</code>' for f in chain.findings_involved)
        items += f"""
        <div class="chain-card">
          <h3>&#9938; {_esc(chain.title)}</h3>
          <div class="chain-meta">
            <span class="chain-badge" style="background:{likelihood_color}22;color:{likelihood_color}">Likelihood: {chain.likelihood}</span>
            <span class="chain-badge" style="background:{impact_color}22;color:{impact_color}">Impact: {chain.impact}</span>
            <span>Findings: {findings_html}</span>
          </div>
          <ol class="chain-steps">{steps}</ol>
        </div>"""
    return f"<section><h2>&#9935; Attack Chains</h2>{items}</section>"


def _render_top10(priorities, findings) -> str:
    if not priorities:
        return ""
    finding_map = {f.id: f for f in findings}
    items = ""
    for i, fid in enumerate(priorities[:10], 1):
        f = finding_map.get(fid)
        if f:
            items += (
                f'<li><span class="top10-num">{i}.</span>'
                f'<span class="sev sev-{_esc(f.severity)}">{_esc(f.severity)}</span>&nbsp;'
                f'<strong>{_esc(f.title)}</strong> &mdash; '
                f'<code>{_esc(f.resource or f.category)}</code></li>'
            )
        else:
            items += f'<li><span class="top10-num">{i}.</span><code>{_esc(fid)}</code></li>'
    return f"<section><h2>&#127919; Top 10 Priorities</h2><ul class='top10-list'>{items}</ul></section>"


def _render_findings_table(findings) -> str:
    if not findings:
        return '<p style="color:var(--text-muted);padding:16px 0;">No findings at this severity threshold.</p>'
    rows = ""
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.severity)):
        evidence_short = (f.evidence[:100] + "...") if len(f.evidence) > 100 else f.evidence
        remediation_short = (f.remediation[:120] + "...") if len(f.remediation) > 120 else f.remediation
        rows += f"""<tr data-severity="{_esc(f.severity)}">
          <td><span class="sev sev-{_esc(f.severity)}">{_esc(f.severity)}</span></td>
          <td><strong>{_esc(f.title)}</strong></td>
          <td><code>{_esc(f.category)}</code></td>
          <td><code>{_esc(f.resource or '--')}</code></td>
          <td style="max-width:280px;">{_esc(f.description)}</td>
          <td title="{_esc(f.evidence)}"><code>{_esc(evidence_short)}</code></td>
          <td><code>{_esc(remediation_short)}</code></td>
        </tr>"""
    return f"""<div style="overflow-x:auto;"><table>
      <thead><tr>
        <th>Severity</th><th>Title</th><th>Module</th>
        <th>Resource</th><th>Description</th><th>Evidence</th><th>Remediation</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table></div>
    <p id="noResults" class="no-results hidden">No findings match your search.</p>"""


def _render_module_sections(module_results) -> str:
    if not module_results:
        return ""
    sections = "<h2>Module Details</h2>"
    for mr in sorted(module_results, key=lambda r: (-r.module_risk_score, r.module_name)):
        finding_count = len(mr.findings)
        error_html = f"<p style='color:#ff4444;margin-bottom:8px'>Error: {_esc(mr.error)}</p>" if mr.error else ""
        summary_html = f"<p style='margin-bottom:12px;color:var(--text-muted);font-size:13px;'>{_esc(mr.module_summary)}</p>" if mr.module_summary else ""

        token_html = ""
        if mr.input_tokens or mr.output_tokens:
            token_html = f" &bull; {mr.input_tokens:,}in/{mr.output_tokens:,}out tokens"

        risk_color = (
            "#ff4444" if mr.module_risk_score >= 70 else
            "#ff8c00" if mr.module_risk_score >= 40 else
            "#ffd700" if mr.module_risk_score >= 20 else
            "#4fc3f7"
        )
        status_icon = "&#10003;" if not mr.error else "&#10007;"

        findings_html = ""
        if mr.findings:
            rows = ""
            for f in sorted(mr.findings, key=lambda x: SEVERITY_ORDER.index(x.severity)):
                rem_short = (f.remediation[:120] + "...") if len(f.remediation) > 120 else f.remediation
                rows += f"""<tr>
                  <td><span class="sev sev-{_esc(f.severity)}">{_esc(f.severity)}</span></td>
                  <td>{_esc(f.title)}</td>
                  <td><code>{_esc(f.resource or '--')}</code></td>
                  <td style="max-width:300px;">{_esc(f.description)}</td>
                  <td><code>{_esc(rem_short)}</code></td>
                </tr>"""
            findings_html = f"""<div style="overflow-x:auto;margin-top:8px;"><table>
              <thead><tr><th>Severity</th><th>Title</th><th>Resource</th><th>Description</th><th>Remediation</th></tr></thead>
              <tbody>{rows}</tbody>
            </table></div>"""

        sections += f"""
        <details class="module-section">
          <summary>
            <span>{status_icon} {_esc(mr.provider.upper())}/{_esc(mr.module_name)}</span>
            <span class="module-meta">
              <span class="risk-score-pill" style="background:{risk_color}22;color:{risk_color}">
                {mr.module_risk_score}/100
              </span>
              <span style="color:var(--text-muted);font-weight:normal;font-size:12px;">
                {finding_count} finding{'s' if finding_count != 1 else ''} &bull;
                {mr.duration_seconds:.1f}s{token_html}
              </span>
            </span>
          </summary>
          <div class="module-content">
            {error_html}{summary_html}{findings_html}
          </div>
        </details>"""

    return f"<section>{sections}</section>"


def _esc(s) -> str:
    """HTML-escape a value."""
    if s is None:
        return ""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))
