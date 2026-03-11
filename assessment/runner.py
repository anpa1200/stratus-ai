"""
Stage 1: parallel scanner execution.
"""
import logging
import concurrent.futures
from assessment.models import ModuleResult

logger = logging.getLogger(__name__)


def run_scanners(scanners: list, max_workers: int = 6) -> list:
    """Run scanner instances in parallel. Returns list[ModuleResult]."""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_scanner = {executor.submit(s.scan): s for s in scanners}
        for future in concurrent.futures.as_completed(future_to_scanner):
            scanner = future_to_scanner[future]
            try:
                result = future.result()
                results.append(result)
                status = "✓" if not result.error else "✗"
                logger.info(f"  {status} {scanner.provider}/{scanner.name:<20} {result.duration_seconds:.1f}s")
            except Exception as e:
                logger.error(f"  ✗ {scanner.name} raised: {e}")
                results.append(ModuleResult(
                    module_name=scanner.name,
                    provider=scanner.provider,
                    raw_output={},
                    findings=[],
                    error=str(e),
                ))

    # Sort by provider then module name for consistent output
    results.sort(key=lambda r: (r.provider, r.module_name))
    return results
