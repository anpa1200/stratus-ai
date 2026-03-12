"""
Stage 2: AI analysis — sequential per-module analysis + cross-module synthesis.
Per-module errors are isolated: one failed module does NOT abort the entire run.
Token usage is tracked and returned for cost estimation.

Improvements over v1:
  - Tiered model selection (cheap model for simple modules)
  - Structural JSON truncation (no mid-JSON cuts)
  - JSON extraction with markdown fallback (no silent drops)
  - Synthesis input pruned to fields needed for attack-chain reasoning
  - Reduced inter-request delay (1s vs 3s)
"""
import json
import time
import logging
from assessment.models import Finding, ModuleResult
from assessment.ai.llm_client import (
    call_llm,
    extract_json,
    structural_truncate,
    select_module_model,
    InsufficientCreditsError,
)
from assessment.ai.preprocessor import preprocess
from assessment.ai.prompts import SYSTEM_PROMPT, MODULE_ANALYSIS_PROMPT, SYNTHESIS_PROMPT
from assessment.config import (
    DEFAULT_MODEL,
    MAX_SCAN_OUTPUT_CHARS,
    INTER_REQUEST_DELAY,
    MODULE_MAX_OUTPUT_TOKENS,
)

logger = logging.getLogger(__name__)


def analyze_modules(
    module_results: list,
    account_id: str = "unknown",
    region: str = "",
    mode: str = "internal",
    model: str = DEFAULT_MODEL,
    account_context: str = "",
) -> dict:
    """
    Run AI analysis on each module sequentially.
    Returns aggregated token usage dict.
    Per-module failures are logged but do NOT raise.
    """
    total_usage = {"input_tokens": 0, "output_tokens": 0}

    for i, mr in enumerate(module_results):
        if mr.error:
            logger.info(f"  Skipping {mr.module_name} (scanner error: {mr.error})")
            continue

        # Select cheapest model that can handle this module well
        effective_model = select_module_model(mr.module_name, model)
        downgraded = effective_model != model

        logger.info(
            f"  Analyzing {mr.provider}/{mr.module_name} "
            f"({i + 1}/{len(module_results)})"
            + (f" [↓ {effective_model}]" if downgraded else "")
            + "..."
        )

        try:
            preprocessed = preprocess(mr.module_name, mr.raw_output)

            # Structural truncation — removes whole list items, never cuts mid-JSON
            if len(json.dumps(preprocessed, default=str)) > MAX_SCAN_OUTPUT_CHARS:
                before = len(json.dumps(preprocessed, default=str))
                preprocessed = structural_truncate(preprocessed, MAX_SCAN_OUTPUT_CHARS)
                after = len(json.dumps(preprocessed, default=str))
                logger.warning(
                    f"  [{mr.module_name}] structurally truncated "
                    f"({before:,} → {after:,} chars)."
                )

            scan_json = json.dumps(preprocessed, default=str, indent=None)

            max_out = MODULE_MAX_OUTPUT_TOKENS.get(
                mr.module_name,
                MODULE_MAX_OUTPUT_TOKENS["_default_module"],
            )

            prompt = MODULE_ANALYSIS_PROMPT.format(
                module_name=mr.module_name,
                provider=mr.provider,
                account_id=account_id,
                region=region,
                mode=mode,
                account_context=account_context or "Production environment — assume sensitive data.",
                scan_output=scan_json,
            )

            raw_response, usage = call_llm(
                effective_model, SYSTEM_PROMPT, prompt, max_tokens=max_out
            )

            # JSON extraction with fallback — never silently drops a module
            parsed = extract_json(raw_response)

            mr.module_risk_score = parsed.get("module_risk_score", 0)
            mr.module_summary = parsed.get("module_summary", "")
            mr.input_tokens = usage.get("input_tokens", 0)
            mr.output_tokens = usage.get("output_tokens", 0)

            total_usage["input_tokens"] += mr.input_tokens
            total_usage["output_tokens"] += mr.output_tokens

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

            cache_note = ""
            cr = usage.get("cache_read_tokens", 0)
            if cr:
                cache_note = f", {cr:,} cached"

            logger.info(
                f"    → {len(mr.findings)} findings, risk {mr.module_risk_score}/100 "
                f"({mr.input_tokens:,}in/{mr.output_tokens:,}out{cache_note})"
            )

        except json.JSONDecodeError as e:
            logger.error(f"  JSON parse failed for {mr.module_name}: {e} — skipping")
        except Exception as e:
            logger.error(f"  AI analysis failed for {mr.module_name}: {e} — skipping")

        if i < len(module_results) - 1:
            time.sleep(INTER_REQUEST_DELAY)

    return total_usage


def synthesize(
    module_results: list,
    model: str = DEFAULT_MODEL,
    account_context: str = "",
) -> tuple[dict, dict]:
    """
    Run synthesis pass — attack chains, priorities, executive summary.
    Returns (synthesis_dict, usage_dict).

    Synthesis input is pruned to only the fields needed for cross-module
    reasoning (excludes 'evidence' and 'remediation' — per-finding concerns
    that inflate token count without improving attack chain analysis).
    """
    # Pruned finding format for synthesis — saves 25-40% vs full finding
    all_findings = []
    for mr in module_results:
        for f in mr.findings:
            all_findings.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "resource": f.resource,
                "description": f.description,   # keep: context for chain reasoning
                "provider": f.provider,
                # excluded: evidence, remediation (not needed for synthesis)
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

    # Structural truncation for synthesis — keep most severe findings
    if len(module_findings_json) > MAX_SCAN_OUTPUT_CHARS * 2:
        # Sort by severity before truncating so low-priority items are dropped first
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        all_findings.sort(key=lambda f: sev_order.get(f.get("severity", "INFO"), 5))
        while len(json.dumps(all_findings, default=str)) > MAX_SCAN_OUTPUT_CHARS * 2:
            all_findings.pop()
        module_findings_json = json.dumps(all_findings, default=str)
        logger.warning(
            f"Synthesis input truncated to {len(all_findings)} highest-severity findings."
        )

    module_summaries = [
        f"{mr.provider}/{mr.module_name}: {mr.module_summary}"
        for mr in module_results
        if mr.module_summary
    ]

    prompt = SYNTHESIS_PROMPT.format(
        num_modules=len(module_results),
        all_module_findings_json=module_findings_json,
        module_summaries="\n".join(module_summaries) if module_summaries else "N/A",
        critical_count=counts["CRITICAL"],
        high_count=counts["HIGH"],
        medium_count=counts["MEDIUM"],
        low_count=counts["LOW"],
        account_context=account_context or "Production environment — assume sensitive data.",
    )

    logger.info("  Running synthesis...")
    raw_response, usage = call_llm(
        model, SYSTEM_PROMPT, prompt,
        max_tokens=MODULE_MAX_OUTPUT_TOKENS["_synthesis"],
    )

    cr = usage.get("cache_read_tokens", 0)
    cache_note = f", {cr:,} cached" if cr else ""
    logger.info(
        f"  Synthesis: {usage.get('input_tokens',0):,}in/"
        f"{usage.get('output_tokens',0):,}out{cache_note}"
    )

    return extract_json(raw_response), usage
