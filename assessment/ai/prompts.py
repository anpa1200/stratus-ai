SYSTEM_PROMPT = """You are a senior cloud security engineer performing an authorized vulnerability \
assessment. You are analyzing raw security scan data collected from a cloud environment.

Rules:
- Be specific: cite exact resource names, ARNs, policy names, and configuration values from the data
- Assign severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO
- For each finding provide: title, severity, description, evidence (exact data from scan), \
remediation (specific command, console action, or Terraform/CLI change)
- Do not invent findings not supported by the data
- Distinguish between misconfiguration (fixable) and inherent exposure (architecture decision)
- Output valid JSON exactly matching the provided schema
- Do not add markdown code fences around the JSON"""


MODULE_ANALYSIS_PROMPT = """Analyze the following {module_name} scan results from a cloud security assessment.

CLOUD CONTEXT:
Provider: {provider}
Account/Project: {account_id}
Region: {region}
Mode: {mode}

RAW SCAN DATA:
{scan_output}

Identify security findings. Return at most 12 findings — prioritise by severity, merge duplicates.
Keep each field concise: description ≤ 2 sentences, evidence ≤ 1 line, remediation ≤ 1 command or action.

Output a JSON object with this exact schema:
{{
  "findings": [
    {{
      "id": "unique_snake_case_id",
      "title": "Short descriptive title",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "category": "{module_name}",
      "resource": "affected resource name/ARN (if applicable)",
      "description": "What the issue is and why it matters (≤2 sentences)",
      "evidence": "Exact values/resource names from the scan data (≤1 line)",
      "remediation": "Specific CLI command, console step, or config change (≤1 line)",
      "references": []
    }}
  ],
  "module_risk_score": 0,
  "module_summary": "2-3 sentence summary of this module's findings"
}}

The module_risk_score should be 0-100. Output only valid JSON, no other text."""


SYNTHESIS_PROMPT = """You have received cloud security assessment findings from {num_modules} scanner modules \
for a single cloud account/environment. Perform a synthesis analysis.

INDIVIDUAL MODULE FINDINGS:
{all_module_findings_json}

QUANTITATIVE SUMMARY:
- Critical findings: {critical_count}
- High findings: {high_count}
- Medium findings: {medium_count}
- Low findings: {low_count}

Tasks:
1. ATTACK CHAINS: Identify 2-5 realistic attack scenarios where findings combine. Be specific to \
the actual findings (e.g., "public S3 bucket X + overprivileged IAM role Y + IMDSv1 on instance Z \
creates credential theft and lateral movement path").
2. PRIORITY ORDER: Rank the top 10 findings by actual exploitability and blast radius on THIS account.
3. EXECUTIVE SUMMARY: 3-5 paragraphs suitable for a cloud account owner or CISO.
4. OVERALL RISK RATING: CRITICAL/HIGH/MEDIUM/LOW with justification.

Output a JSON object with this exact schema:
{{
  "overall_risk_rating": "CRITICAL|HIGH|MEDIUM|LOW",
  "overall_risk_score": 0,
  "executive_summary": "...",
  "attack_chains": [
    {{
      "title": "...",
      "steps": ["step1", "step2"],
      "findings_involved": ["finding_id_1"],
      "likelihood": "HIGH|MEDIUM|LOW",
      "impact": "HIGH|MEDIUM|LOW"
    }}
  ],
  "top_10_priorities": ["finding_id_1"],
  "recommended_immediate_actions": ["action1"]
}}

Output only valid JSON, no other text."""
