"""
Data models for cloud security assessment.
"""
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class Finding:
    id: str
    title: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: str          # scanner module name
    description: str
    evidence: str
    remediation: str
    resource: str = ""     # affected cloud resource ARN/name
    region: str = ""
    provider: str = ""     # aws | gcp | azure | external
    references: list = field(default_factory=list)


@dataclass
class ModuleResult:
    module_name: str
    provider: str
    raw_output: dict
    findings: list         # list[Finding] — populated by AI
    module_risk_score: int = 0
    module_summary: str = ""
    duration_seconds: float = 0.0
    error: Optional[str] = None
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class AttackChain:
    title: str
    steps: list            # list[str]
    findings_involved: list  # list[str] finding IDs
    likelihood: str        # HIGH | MEDIUM | LOW
    impact: str            # HIGH | MEDIUM | LOW


@dataclass
class Report:
    scan_id: str
    timestamp: datetime
    provider: str
    account_id: str
    regions: list          # list[str]
    mode: str              # internal | external | both
    module_results: list   # list[ModuleResult]
    findings: list         # list[Finding] — all findings merged
    attack_chains: list    # list[AttackChain]
    top_10_priorities: list  # list[str] finding IDs
    recommended_immediate_actions: list  # list[str]
    overall_risk_rating: str = "UNKNOWN"
    overall_risk_score: int = 0
    executive_summary: str = ""
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    estimated_cost_usd: float = 0.0
    model_used: str = ""
