"""
StratusAI — Cloud Security Assessment CLI.
"""
import os
import sys
import uuid
import json
import logging
import click
from datetime import datetime, timezone
from pathlib import Path

from assessment.models import Report, AttackChain, Finding
from assessment.runner import run_scanners
from assessment.ai.analyzer import analyze_modules, synthesize
from assessment.ai.client import InsufficientCreditsError
from assessment.config import DEFAULT_MODEL, DEFAULT_AWS_REGIONS


def _setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(message)s",
        level=level,
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    # Suppress noisy AWS SDK logs
    for noisy in ("botocore", "boto3", "urllib3", "s3transfer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


@click.command()
@click.option("--provider", default="aws", type=click.Choice(["aws", "gcp", "azure"]),
              show_default=True, help="Cloud provider to assess")
@click.option("--mode", default="both", type=click.Choice(["internal", "external", "both"]),
              show_default=True, help="Assessment mode")
@click.option("--target", default="", help="Hostname/IP for external mode")
@click.option("--region", default="", help="Cloud region (default: us-east-1 for AWS)")
@click.option("--all-regions", is_flag=True, help="Scan all default regions (AWS)")
@click.option("--profile", default="", help="AWS CLI profile name")
@click.option("--modules", default="", help="Comma-separated list of modules to run")
@click.option("--skip", default="", help="Comma-separated list of modules to skip")
@click.option("--no-ai", is_flag=True, help="Skip AI analysis (raw scanner output only)")
@click.option("--severity", default="INFO",
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
              show_default=True, help="Minimum severity to include in report")
@click.option("--model", default=DEFAULT_MODEL, show_default=True,
              help="Claude model to use")
@click.option("--output-dir", default="./output", show_default=True,
              help="Directory for report output")
@click.option("--verbose", is_flag=True, help="Verbose logging")
def main(provider, mode, target, region, all_regions, profile, modules, skip,
         no_ai, severity, model, output_dir, verbose):
    """StratusAI — Dockerized cloud security assessment with AI-powered analysis."""

    _setup_logging(verbose)
    log = logging.getLogger(__name__)

    # ── Resolve regions ──────────────────────────────────────────────────────
    if all_regions:
        regions = DEFAULT_AWS_REGIONS
    elif region:
        regions = [region]
    else:
        regions = ["us-east-1"] if provider == "aws" else ["global"]

    # ── Build scanner list ───────────────────────────────────────────────────
    session = None
    account_id = "unknown"

    if provider == "aws" and mode in ("internal", "both"):
        try:
            import boto3
            kwargs = {}
            if profile:
                kwargs["profile_name"] = profile
            session = boto3.Session(**kwargs)
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            account_id = identity["Account"]
            log.info(f"AWS Account: {account_id} ({identity.get('Arn', '')})")
        except Exception as e:
            log.error(f"AWS authentication failed: {e}")
            log.error("Ensure AWS credentials are configured (env vars, ~/.aws/credentials, or IAM role)")
            if mode == "internal":
                sys.exit(1)
            log.warning("Continuing with external scan only")
            mode = "external"

    # Select modules
    scanners = _build_scanners(provider, mode, session, regions, target, modules, skip)

    if not scanners:
        log.error("No scanners to run. Check --modules / --mode / --target options.")
        sys.exit(1)

    # ── Stage 1: Scan ────────────────────────────────────────────────────────
    log.info(f"\n► Running {len(scanners)} scanner modules...")
    module_names = ", ".join(f"{s.provider}/{s.name}" for s in scanners)
    log.info(f"  Modules: {module_names}\n")

    module_results = run_scanners(scanners)

    if no_ai:
        # Write raw JSON and exit
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
        raw_file = out_path / f"raw_{ts}.json"
        raw_data = [
            {
                "module": mr.module_name,
                "provider": mr.provider,
                "error": mr.error,
                "raw_output": mr.raw_output,
            }
            for mr in module_results
        ]
        raw_file.write_text(json.dumps(raw_data, default=str, indent=2))
        log.info(f"\n► Raw output: {raw_file}")
        return

    # ── Stage 2: AI Analysis ─────────────────────────────────────────────────
    log.info(f"\n► Running AI analysis ({model})...")
    log.info("  Analyzing modules...")

    try:
        analyze_modules(
            module_results,
            account_id=account_id,
            region=", ".join(regions),
            mode=mode,
            model=model,
        )
        log.info("  Running synthesis...")
        synthesis = synthesize(module_results, model=model)
    except InsufficientCreditsError as e:
        log.error(f"\n{e}")
        log.error("Use --no-ai to run without AI analysis.")
        sys.exit(1)
    except Exception as e:
        log.error(f"\nAI analysis failed: {e}")
        log.error("Use --no-ai to generate raw output only.")
        sys.exit(1)

    # ── Build Report ─────────────────────────────────────────────────────────
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_threshold = sev_order.index(severity)

    all_findings = []
    for mr in module_results:
        for f in mr.findings:
            if sev_order.index(f.severity) <= sev_threshold:
                all_findings.append(f)

    attack_chains = [
        AttackChain(
            title=ac["title"],
            steps=ac["steps"],
            findings_involved=ac.get("findings_involved", []),
            likelihood=ac.get("likelihood", "MEDIUM"),
            impact=ac.get("impact", "MEDIUM"),
        )
        for ac in synthesis.get("attack_chains", [])
    ]

    report = Report(
        scan_id=str(uuid.uuid4())[:8],
        timestamp=datetime.now(timezone.utc),
        provider=provider,
        account_id=account_id,
        regions=regions,
        mode=mode,
        module_results=module_results,
        findings=all_findings,
        attack_chains=attack_chains,
        top_10_priorities=synthesis.get("top_10_priorities", []),
        recommended_immediate_actions=synthesis.get("recommended_immediate_actions", []),
        overall_risk_rating=synthesis.get("overall_risk_rating", "UNKNOWN"),
        overall_risk_score=synthesis.get("overall_risk_score", 0),
        executive_summary=synthesis.get("executive_summary", ""),
    )

    # ── Stage 3: Reports ─────────────────────────────────────────────────────
    log.info(f"\n► Generating reports...")

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    ts = report.timestamp.strftime("%Y-%m-%dT%H-%M-%SZ")

    from assessment.reports.html import generate_html
    from assessment.reports.markdown import generate_markdown

    html_file = out_path / f"report_{ts}.html"
    md_file = out_path / f"report_{ts}.md"

    html_file.write_text(generate_html(report), encoding="utf-8")
    md_file.write_text(generate_markdown(report), encoding="utf-8")

    log.info(f"  HTML:     {html_file}")
    log.info(f"  Markdown: {md_file}")

    # ── Summary ──────────────────────────────────────────────────────────────
    counts = {s: 0 for s in sev_order}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    top_action = report.recommended_immediate_actions[0] if report.recommended_immediate_actions else "—"
    if len(top_action) > 80:
        top_action = top_action[:77] + "..."

    print(f"""
╔══════════════════ SUMMARY ══════════════════╗
  Overall Risk: {report.overall_risk_rating} ({report.overall_risk_score}/100)
  Provider: {provider.upper()} — {account_id}
  Findings:
    {counts['CRITICAL']} Critical  {counts['HIGH']} High  {counts['MEDIUM']} Medium  {counts['LOW']} Low

  Top Action: {top_action}
╚══════════════════════════════════════════════╝""")


def _build_scanners(provider, mode, session, regions, target, modules_str, skip_str):
    """Build the list of scanner instances to run."""
    requested = set(modules_str.split(",")) - {""} if modules_str else None
    skipped = set(skip_str.split(",")) - {""} if skip_str else set()
    scanners = []

    # Internal (cloud API) scanners
    if mode in ("internal", "both") and session:
        if provider == "aws":
            from assessment.scanners.aws import AWS_SCANNERS
            for region in regions:
                for name, cls in AWS_SCANNERS.items():
                    if name in skipped:
                        continue
                    if requested and name not in requested:
                        continue
                    scanners.append(cls(session=session, region=region))

    # External scanners
    if mode in ("external", "both"):
        if not target and mode == "external":
            import click
            raise click.UsageError("--target is required for external mode")
        if target:
            from assessment.scanners.external import EXTERNAL_SCANNERS
            for name, cls in EXTERNAL_SCANNERS.items():
                if name in skipped:
                    continue
                if requested and name not in requested:
                    continue
                scanners.append(cls(target=target))

    return scanners


if __name__ == "__main__":
    main()
