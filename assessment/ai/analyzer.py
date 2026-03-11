"""
Stage 2: AI analysis — sequential per-module analysis + cross-module synthesis.
"""
import json
import time
import logging
from assessment.models import Finding, ModuleResult, AttackChain
from assessment.ai.client import call_claude
from assessment.ai.preprocessor import preprocess
from assessment.ai.prompts import SYSTEM_PROMPT, MODULE_ANALYSIS_PROMPT, SYNTHESIS_PROMPT
from assessment.config import DEFAULT_MODEL, MAX_SCAN_OUTPUT_CHARS, INTER_REQUEST_DELAY

logger = logging.getLogger(__name__)


def analyze_modules(
    module_results: list,   # list[ModuleResult]
    account_id: str = "unknown",
    region: str = "",
    mode: str = "internal",
    model: str = DEFAULT_MODEL,
) -> list:
    """Run AI analysis on each module sequentially. Returns updated module_results."""
    for i, mr in enumerate(module_results):
        if mr.error:
            logger.info(f"  Skipping {mr.module_name} (scanner error)")
            continue

        logger.info(f"  Analyzing {mr.module_name} ({i + 1}/{len(module_results)})...")

        try:
            preprocessed = preprocess(mr.module_name, mr.raw_output)
            scan_json = json.dumps(preprocessed, default=str, indent=None)

            if len(scan_json) > MAX_SCAN_OUTPUT_CHARS:
                scan_json = scan_json[:MAX_SCAN_OUTPUT_CHARS] + "\n... [truncated]"

            prompt = MODULE_ANALYSIS_PROMPT.format(
                module_name=mr.module_name,
                provider=mr.provider,
                account_id=account_id,
                region=region,
                mode=mode,
                scan_output=scan_json,
            )

            raw_response = call_claude(model, SYSTEM_PROMPT, prompt, max_tokens=8192)
            parsed = json.loads(raw_response)

            mr.module_risk_score = parsed.get("module_risk_score", 0)
            mr.module_summary = parsed.get("module_summary", "")

            for f_data in parsed.get("findings", []):
                mr.findings.append(Finding(
                    id=f_data.get("id", ""),
                    title=f_data.get("title", ""),
                    severity=f_data.get("severity", "INFO"),
                    category=f_data.get("category", mr.module_name),
                    resource=f_data.get("resource", ""),
                    description=f_data.get("description", ""),
                    evidence=f_data.get("evidence", ""),
                    remediation=f_data.get("remediation", ""),
                    provider=mr.provider,
                    references=f_data.get("references", []),
                ))

        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error for {mr.module_name}: {e}")
        except Exception as e:
            logger.error(f"AI analysis failed for {mr.module_name}: {e}")
            raise

        if i < len(module_results) - 1:
            time.sleep(INTER_REQUEST_DELAY)

    return module_results


def synthesize(
    module_results: list,
    model: str = DEFAULT_MODEL,
) -> dict:
    """Run synthesis pass — attack chains, priorities, executive summary."""
    all_findings = []
    for mr in module_results:
        for f in mr.findings:
            all_findings.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "resource": f.resource,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "provider": f.provider,
            })

    counts = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for f in all_findings:
        sev = f.get("severity", "").upper()
        if sev in counts:
            counts[sev] += 1

    if not all_findings:
        return {
            "overall_risk_rating": "LOW",
            "overall_risk_score": 0,
            "executive_summary": "No findings identified.",
            "attack_chains": [],
            "top_10_priorities": [],
            "recommended_immediate_actions": [],
        }

    module_findings_json = json.dumps(all_findings, default=str)
    if len(module_findings_json) > MAX_SCAN_OUTPUT_CHARS * 2:
        module_findings_json = module_findings_json[:MAX_SCAN_OUTPUT_CHARS * 2] + "..."

    prompt = SYNTHESIS_PROMPT.format(
        num_modules=len(module_results),
        all_module_findings_json=module_findings_json,
        critical_count=counts["CRITICAL"],
        high_count=counts["HIGH"],
        medium_count=counts["MEDIUM"],
        low_count=counts["LOW"],
    )

    logger.info("  Running synthesis...")
    raw_response = call_claude(model, SYSTEM_PROMPT, prompt, max_tokens=8192)
    return json.loads(raw_response)
