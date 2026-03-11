"""
Stage 2: AI analysis — sequential per-module analysis + cross-module synthesis.
Per-module errors are isolated: one failed module does NOT abort the entire run.
Token usage is tracked and returned for cost estimation.
"""
import json
import time
import logging
from assessment.models import Finding, ModuleResult
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
) -> dict:
    """
    Run AI analysis on each module sequentially.
    Returns aggregated token usage dict.
    Per-module failures are logged but do NOT raise — the run continues.
    """
    total_usage = {"input_tokens": 0, "output_tokens": 0}

    for i, mr in enumerate(module_results):
        if mr.error:
            logger.info(f"  Skipping {mr.module_name} (scanner error: {mr.error})")
            continue

        logger.info(f"  Analyzing {mr.provider}/{mr.module_name} ({i + 1}/{len(module_results)})...")

        try:
            preprocessed = preprocess(mr.module_name, mr.raw_output)
            scan_json = json.dumps(preprocessed, default=str, indent=None)

            if len(scan_json) > MAX_SCAN_OUTPUT_CHARS:
                logger.warning(
                    f"  [{mr.module_name}] scan output truncated "
                    f"({len(scan_json):,} -> {MAX_SCAN_OUTPUT_CHARS:,} chars). "
                    "Some findings may be missed. Consider --modules to split the scan."
                )
                scan_json = scan_json[:MAX_SCAN_OUTPUT_CHARS] + "\n... [truncated]"

            prompt = MODULE_ANALYSIS_PROMPT.format(
                module_name=mr.module_name,
                provider=mr.provider,
                account_id=account_id,
                region=region,
                mode=mode,
                scan_output=scan_json,
            )

            raw_response, usage = call_claude(model, SYSTEM_PROMPT, prompt, max_tokens=8192)

            # Accumulate token usage
            mr.input_tokens = usage.get("input_tokens", 0)
            mr.output_tokens = usage.get("output_tokens", 0)
            total_usage["input_tokens"] += mr.input_tokens
            total_usage["output_tokens"] += mr.output_tokens

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

            logger.info(
                f"    -> {len(mr.findings)} findings, risk score {mr.module_risk_score}/100 "
                f"({mr.input_tokens:,}in/{mr.output_tokens:,}out tokens)"
            )

        except json.JSONDecodeError as e:
            logger.error(f"  JSON decode error for {mr.module_name}: {e} — skipping module")
        except Exception as e:
            logger.error(f"  AI analysis failed for {mr.module_name}: {e} — skipping module")

        if i < len(module_results) - 1:
            time.sleep(INTER_REQUEST_DELAY)

    return total_usage


def synthesize(
    module_results: list,
    model: str = DEFAULT_MODEL,
) -> tuple[dict, dict]:
    """
    Run synthesis pass — attack chains, priorities, executive summary.
    Returns (synthesis_dict, usage_dict).
    """
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

    empty_usage = {"input_tokens": 0, "output_tokens": 0}

    if not all_findings:
        return {
            "overall_risk_rating": "LOW",
            "overall_risk_score": 0,
            "executive_summary": "No security findings identified during this assessment.",
            "attack_chains": [],
            "top_10_priorities": [],
            "recommended_immediate_actions": [],
        }, empty_usage

    module_findings_json = json.dumps(all_findings, default=str)
    if len(module_findings_json) > MAX_SCAN_OUTPUT_CHARS * 2:
        logger.warning(
            f"Synthesis input truncated ({len(module_findings_json):,} chars). "
            "Very large finding sets may lose low-severity items."
        )
        module_findings_json = module_findings_json[:MAX_SCAN_OUTPUT_CHARS * 2] + "..."

    # Include per-module summaries for richer synthesis context
    module_summaries = []
    for mr in module_results:
        if mr.module_summary:
            module_summaries.append(f"{mr.provider}/{mr.module_name}: {mr.module_summary}")

    prompt = SYNTHESIS_PROMPT.format(
        num_modules=len(module_results),
        all_module_findings_json=module_findings_json,
        module_summaries="\n".join(module_summaries) if module_summaries else "N/A",
        critical_count=counts["CRITICAL"],
        high_count=counts["HIGH"],
        medium_count=counts["MEDIUM"],
        low_count=counts["LOW"],
    )

    logger.info("  Running synthesis...")
    raw_response, usage = call_claude(model, SYSTEM_PROMPT, prompt, max_tokens=8192)
    logger.info(f"  Synthesis: {usage.get('input_tokens', 0):,}in/{usage.get('output_tokens', 0):,}out tokens")

    return json.loads(raw_response), usage
