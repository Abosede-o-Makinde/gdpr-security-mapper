"""Compliance result models — output of the mapping engine."""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class ComplianceStatus(str, Enum):
    SATISFIED = "SATISFIED"
    PARTIAL = "PARTIAL"
    GAP = "GAP"
    NA = "N/A"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class CheckResult:
    check_id: str
    article_id: str
    control_name: str
    description: str
    status: ComplianceStatus
    evidence: str
    finding: str
    remediation: str
    severity: Severity
    weight: float = 1.0

    @property
    def score(self) -> float:
        return {
            ComplianceStatus.SATISFIED: 1.0,
            ComplianceStatus.PARTIAL: 0.5,
            ComplianceStatus.GAP: 0.0,
            ComplianceStatus.NA: 1.0,
        }[self.status]

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "article_id": self.article_id,
            "control_name": self.control_name,
            "description": self.description,
            "status": self.status.value,
            "evidence": self.evidence,
            "finding": self.finding,
            "remediation": self.remediation,
            "severity": self.severity.value,
            "weight": self.weight,
            "score": self.score,
        }


@dataclass
class ArticleResult:
    article_id: str
    article_title: str
    article_summary: str
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def score(self) -> float:
        active = [c for c in self.checks if c.status != ComplianceStatus.NA]
        if not active:
            return 1.0
        total_weight = sum(c.weight for c in active)
        weighted_score = sum(c.score * c.weight for c in active)
        return weighted_score / total_weight if total_weight else 1.0

    @property
    def status(self) -> ComplianceStatus:
        s = self.score
        if s >= 0.80:
            return ComplianceStatus.SATISFIED
        if s >= 0.45:
            return ComplianceStatus.PARTIAL
        return ComplianceStatus.GAP

    @property
    def gap_count(self) -> int:
        return sum(1 for c in self.checks if c.status == ComplianceStatus.GAP)

    @property
    def partial_count(self) -> int:
        return sum(1 for c in self.checks if c.status == ComplianceStatus.PARTIAL)

    @property
    def satisfied_count(self) -> int:
        return sum(1 for c in self.checks if c.status == ComplianceStatus.SATISFIED)

    @property
    def top_finding(self) -> str:
        gaps = [c for c in self.checks if c.status == ComplianceStatus.GAP]
        if gaps:
            return gaps[0].finding
        partials = [c for c in self.checks if c.status == ComplianceStatus.PARTIAL]
        if partials:
            return partials[0].finding
        return "All controls satisfied."

    def to_dict(self) -> dict:
        return {
            "article_id": self.article_id,
            "article_title": self.article_title,
            "score": round(self.score, 3),
            "status": self.status.value,
            "gap_count": self.gap_count,
            "partial_count": self.partial_count,
            "satisfied_count": self.satisfied_count,
            "checks": [c.to_dict() for c in self.checks],
        }


@dataclass
class ComplianceReport:
    system_name: str
    system_description: str
    generated_at: datetime
    config_source: str
    articles: list[ArticleResult] = field(default_factory=list)
    special_category_data: bool = False

    @property
    def overall_score(self) -> float:
        if not self.articles:
            return 0.0
        return sum(a.score for a in self.articles) / len(self.articles)

    @property
    def _satisfied_threshold(self) -> float:
        """Raise bar to 90% when special category data is present (Art.9 risk uplift)."""
        return 0.90 if self.special_category_data else 0.80

    @property
    def overall_status(self) -> ComplianceStatus:
        s = self.overall_score
        if s >= self._satisfied_threshold:
            return ComplianceStatus.SATISFIED
        if s >= 0.45:
            return ComplianceStatus.PARTIAL
        return ComplianceStatus.GAP

    @property
    def config_confidence(self) -> float:
        """Fraction of checks that have real evidence (not 'Not assessed').

        Low confidence means many fields were omitted from the config — the
        score is less reliable and more controls may be under-assessed.
        """
        all_checks = [c for a in self.articles for c in a.checks]
        if not all_checks:
            return 0.0
        assessed = sum(1 for c in all_checks if c.status != ComplianceStatus.NA and c.evidence != "Not assessed")
        return assessed / len(all_checks)

    @property
    def all_gaps(self) -> list[CheckResult]:
        gaps = [c for a in self.articles for c in a.checks if c.status == ComplianceStatus.GAP]
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return sorted(gaps, key=lambda c: severity_order.get(c.severity, 5))

    @property
    def all_partials(self) -> list[CheckResult]:
        return [c for a in self.articles for c in a.checks if c.status == ComplianceStatus.PARTIAL]

    @property
    def total_checks(self) -> int:
        return sum(len(a.checks) for a in self.articles)

    def to_dict(self) -> dict:
        return {
            "system_name": self.system_name,
            "system_description": self.system_description,
            "generated_at": self.generated_at.isoformat(),
            "config_source": self.config_source,
            "overall_score": round(self.overall_score, 3),
            "overall_status": self.overall_status.value,
            "special_category_data": self.special_category_data,
            "config_confidence": round(self.config_confidence, 3),
            "total_checks": self.total_checks,
            "articles": [a.to_dict() for a in self.articles],
        }
