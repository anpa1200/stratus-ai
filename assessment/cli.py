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


def _resolve_anthropic_key() -> str:
    """
    Resolve Anthropic API key from environment or SSM Parameter Store.
    SSM is used when running as an ECS task (no env vars with secrets).
    """
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if key:
        return key

    ssm_name = os.environ.get("ANTHROPIC_API_KEY_SSM", "")
    if ssm_name:
        try:
            import boto3
            ssm = boto3.client("ssm")
            resp = ssm.get_parameter(Name=ssm_name, WithDecryption=True)
            return resp["Parameter"]["Value"]
        except Exception as e:
            logging.getLogger(__name__).warning(f"SSM key fetch failed: {e}")

    return ""


def _upload_to_s3(local_path: Path, bucket: str, prefix: str, log):
    """Upload a file to S3. Called after local report generation."""
    try:
        import boto3
        s3 = boto3.client("s3")
        key = f"{prefix.rstrip('/')}/{local_path.name}"
        s3.upload_file(str(local_path), bucket, key)
        log.info(f"  S3:       s3://{bucket}/{key}")
    except Exception as e:
        log.warning(f"  S3 upload failed: {e}")


def _setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(message)s",
        level=level,
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    # Suppress noisy SDK logs
    for noisy in (
        "botocore", "boto3", "urllib3", "s3transfer",
        "google.auth", "google.api_core", "google.auth.transport",
        "googleapiclient.discovery", "googleapiclient.discovery_cache",
    ):
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
@click.option("--project", default="", envvar="GOOGLE_CLOUD_PROJECT",
              help="GCP project ID (GCP only; also reads GOOGLE_CLOUD_PROJECT env var)")
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
@click.option("--output-s3", default="", envvar="OUTPUT_S3_BUCKET",
              help="S3 bucket name to upload reports (also reads OUTPUT_S3_BUCKET env var)")
@click.option("--output-s3-prefix", default="reports/", show_default=True, envvar="OUTPUT_S3_PREFIX",
              help="S3 key prefix for uploaded reports")
@click.option("--verbose", is_flag=True, help="Verbose logging")
def main(provider, mode, target, region, all_regions, profile, project, modules, skip,
         no_ai, severity, model, output_dir, output_s3, output_s3_prefix, verbose):
    """StratusAI — AI-powered cloud security assessment tool."""

    _setup_logging(verbose)
    log = logging.getLogger(__name__)

    # ── Provider availability check ───────────────────────────────────────────
    if provider == "azure":
        log.error("Provider 'azure' is not yet implemented.")
        log.error("External scanning works for any provider: --mode external --target <host>")
        sys.exit(1)

    # ── Resolve Anthropic API key (env var or SSM) ────────────────────────────
    if not no_ai:
        api_key = _resolve_anthropic_key()
        if api_key:
            os.environ["ANTHROPIC_API_KEY"] = api_key
        else:
            log.error("ANTHROPIC_API_KEY is not set. Use --no-ai to skip AI analysis.")
            log.error("  export ANTHROPIC_API_KEY=sk-ant-...")
            log.error("  Or set ANTHROPIC_API_KEY_SSM to an SSM parameter name.")
            sys.exit(1)

    # ── Resolve regions ──────────────────────────────────────────────────────
    if all_regions:
        regions = DEFAULT_AWS_REGIONS
    elif region:
        regions = [region]
    elif provider == "gcp":
        regions = ["us-central1"]
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

    if provider == "gcp" and mode in ("internal", "both"):
        try:
            import google.auth
            from assessment.scanners.gcp import GCPSession
            scopes = ["https://www.googleapis.com/auth/cloud-platform"]
            credentials, detected_project = google.auth.default(scopes=scopes)
            gcp_project = project or detected_project or ""
            if not gcp_project:
                log.error("GCP project ID not found. Set GOOGLE_CLOUD_PROJECT or use --project.")
                if mode == "internal":
                    sys.exit(1)
                log.warning("Continuing with external scan only")
                mode = "external"
            else:
                session = GCPSession(credentials=credentials, project_id=gcp_project)
                account_id = gcp_project
                log.info(f"GCP Project: {gcp_project}")
        except Exception as e:
            log.error(f"GCP authentication failed: {e}")
            log.error(
                "Ensure credentials are configured:\n"
                "  gcloud auth application-default login\n"
                "  or set GOOGLE_APPLICATION_CREDENTIALS to a service account key file"
            )
            if mode == "internal":
                sys.exit(1)
            log.warning("Continuing with external scan only")
            mode = "external"

    # ── External target validation ────────────────────────────────────────────
    if mode == "external" and not target:
        log.error("--target <hostname/IP> is required for --mode external")
        sys.exit(1)
    if mode == "both" and not target:
        log.warning("--target not provided; running internal-only (no external scans).")
        mode = "internal"

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
        if output_s3:
            _upload_to_s3(raw_file, output_s3, output_s3_prefix, log)
        return

    # ── Stage 2: AI Analysis ─────────────────────────────────────────────────
    log.info(f"\n► Running AI analysis ({model})...")
    log.info("  Analyzing modules...")

    try:
        token_usage = analyze_modules(
            module_results,
            account_id=account_id,
            region=", ".join(regions),
            mode=mode,
            model=model,
        )
        log.info("  Running synthesis...")
        synthesis, synth_usage = synthesize(module_results, model=model)
    except InsufficientCreditsError as e:
        log.error(f"\n{e}")
        log.error("Use --no-ai to run without AI analysis.")
        sys.exit(1)
    except Exception as e:
        log.error(f"\nAI analysis failed: {e}")
        log.error("Use --no-ai to generate raw output only.")
        sys.exit(1)

    # Aggregate token usage
    total_input = token_usage.get("input_tokens", 0) + synth_usage.get("input_tokens", 0)
    total_output = token_usage.get("output_tokens", 0) + synth_usage.get("output_tokens", 0)

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

    from assessment.ai.client import estimate_cost
    estimated_cost = estimate_cost(model, total_input, total_output)

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
        total_input_tokens=total_input,
        total_output_tokens=total_output,
        estimated_cost_usd=estimated_cost,
        model_used=model,
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

    # ── Upload to S3 (if configured) ─────────────────────────────────────────
    if output_s3:
        _upload_to_s3(html_file, output_s3, output_s3_prefix, log)
        _upload_to_s3(md_file, output_s3, output_s3_prefix, log)

    # ── Summary ──────────────────────────────────────────────────────────────
    counts = {s: 0 for s in sev_order}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    top_action = report.recommended_immediate_actions[0] if report.recommended_immediate_actions else "—"
    if len(top_action) > 80:
        top_action = top_action[:77] + "..."

    print(f"""
╔══════════════════════ SUMMARY ════════════════════════╗
  Overall Risk: {report.overall_risk_rating} ({report.overall_risk_score}/100)
  Provider: {provider.upper()} — {account_id}
  Findings:
    {counts['CRITICAL']} Critical  {counts['HIGH']} High  {counts['MEDIUM']} Medium  {counts['LOW']} Low

  Top Action: {top_action}

  AI Cost: ${estimated_cost:.4f} ({total_input:,} in / {total_output:,} out tokens)
╚════════════════════════════════════════════════════════╝""")


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

        elif provider == "gcp":
            from assessment.scanners.gcp import GCP_SCANNERS
            for region in regions:
                for name, cls in GCP_SCANNERS.items():
                    if name in skipped:
                        continue
                    if requested and name not in requested:
                        continue
                    scanners.append(cls(session=session, region=region))

    # External scanners
    if mode in ("external", "both") and target:
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
