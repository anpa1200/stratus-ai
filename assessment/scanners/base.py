"""
Abstract base scanner for cloud security modules.
"""
import logging
import time
from abc import ABC, abstractmethod
from assessment.models import ModuleResult

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    name: str = "base"
    provider: str = "unknown"

    def __init__(self, session=None, region: str = "", target: str = ""):
        """
        session: provider SDK session (boto3.Session for AWS, etc.)
        region:  cloud region to scan
        target:  hostname/IP for external scans
        """
        self.session = session
        self.region = region
        self.target = target

    def scan(self) -> ModuleResult:
        """Run the scanner, return a ModuleResult with error isolation."""
        start = time.time()
        try:
            raw, findings = self._scan()
            return ModuleResult(
                module_name=self.name,
                provider=self.provider,
                raw_output=raw,
                findings=findings,
                duration_seconds=time.time() - start,
            )
        except Exception as e:
            logger.error(f"Scanner {self.name} failed: {e}")
            return ModuleResult(
                module_name=self.name,
                provider=self.provider,
                raw_output={"error": str(e)},
                findings=[],
                duration_seconds=time.time() - start,
                error=str(e),
            )

    @abstractmethod
    def _scan(self) -> tuple[dict, list]:
        """Return (raw_output_dict, []) — AI identifies findings from raw_output."""
        ...
