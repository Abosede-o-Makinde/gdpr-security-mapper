"""Tests for the compliance engine — checks and mapper."""

from __future__ import annotations
import pytest

from gdpr_mapper.engine import run_assessment
from gdpr_mapper.engine.checks import ALL_CHECKS, CHECKS_BY_ARTICLE
from gdpr_mapper.models.compliance import ComplianceStatus, Severity


# ---------------------------------------------------------------------------
# Smoke tests — engine wiring
# ---------------------------------------------------------------------------

class TestCheckRegistry:
    def test_all_checks_present(self):
        assert len(ALL_CHECKS) == 62

    def test_all_checks_have_ids(self):
        ids = [c.id for c in ALL_CHECKS]
        assert len(set(ids)) == len(ids), "Duplicate check IDs found"

    def test_checks_by_article_coverage(self):
        expected_articles = {
            "Art.5(1)(f)", "Art.5(1)(b)", "Art.5(1)(e)",
            "Art.25", "Art.30",
            "Art.32(1)(a)", "Art.32(1)(b)", "Art.32(1)(c)", "Art.32(1)(d)",
            "Art.33", "Art.35", "Art.44",
            "Art.13", "Art.17",
        }
        assert set(CHECKS_BY_ARTICLE.keys()) == expected_articles

    def test_checks_have_remediation(self):
        for check in ALL_CHECKS:
            assert check.remediation, f"{check.id} has no remediation guidance"

    def test_checks_have_valid_severity(self):
        valid = set(Severity)
        for check in ALL_CHECKS:
            assert check.severity in valid, f"{check.id} has invalid severity"


# ---------------------------------------------------------------------------
# Compliant config — most checks should be SATISFIED
# ---------------------------------------------------------------------------

class TestCompliantConfig:
    def test_overall_score_high(self, compliant_config):
        report = run_assessment(compliant_config)
        assert report.overall_score >= 0.80, (
            f"Expected score >= 80%, got {report.overall_score * 100:.1f}%"
        )

    def test_overall_status_satisfied(self, compliant_config):
        report = run_assessment(compliant_config)
        assert report.overall_status == ComplianceStatus.SATISFIED

    def test_few_gaps(self, compliant_config):
        report = run_assessment(compliant_config)
        assert len(report.all_gaps) <= 3, (
            f"Expected ≤3 gaps, got {len(report.all_gaps)}: "
            f"{[g.check_id for g in report.all_gaps]}"
        )

    def test_system_name_preserved(self, compliant_config):
        report = run_assessment(compliant_config)
        assert report.system_name == "Test System"

    def test_article_count(self, compliant_config):
        report = run_assessment(compliant_config)
        assert len(report.articles) == 14

    def test_encryption_article_satisfied(self, compliant_config):
        report = run_assessment(compliant_config)
        art = next(a for a in report.articles if a.article_id == "Art.32(1)(a)")
        assert art.score >= 0.80

    def test_breach_notification_article_satisfied(self, compliant_config):
        report = run_assessment(compliant_config)
        art = next(a for a in report.articles if a.article_id == "Art.33")
        assert art.score >= 0.80


# ---------------------------------------------------------------------------
# Gap config — most checks should be GAP
# ---------------------------------------------------------------------------

class TestGapConfig:
    def test_overall_score_low(self, gap_config):
        report = run_assessment(gap_config)
        assert report.overall_score <= 0.35, (
            f"Expected score <= 35%, got {report.overall_score * 100:.1f}%"
        )

    def test_overall_status_gap(self, gap_config):
        report = run_assessment(gap_config)
        assert report.overall_status == ComplianceStatus.GAP

    def test_many_gaps(self, gap_config):
        report = run_assessment(gap_config)
        assert len(report.all_gaps) >= 20

    def test_gaps_sorted_by_severity(self, gap_config):
        report = run_assessment(gap_config)
        sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                     Severity.LOW: 3, Severity.INFO: 4}
        gaps = report.all_gaps
        for i in range(len(gaps) - 1):
            assert sev_order[gaps[i].severity] <= sev_order[gaps[i + 1].severity], (
                f"Gaps not severity-sorted at position {i}"
            )

    def test_at_rest_encryption_gap(self, gap_config):
        report = run_assessment(gap_config)
        check = next(
            c for a in report.articles for c in a.checks if c.check_id == "ART5-001"
        )
        assert check.status == ComplianceStatus.GAP

    def test_mfa_gap(self, gap_config):
        report = run_assessment(gap_config)
        check = next(
            c for a in report.articles for c in a.checks if c.check_id == "ART5-003"
        )
        assert check.status == ComplianceStatus.GAP

    def test_management_ports_gap(self, gap_config):
        report = run_assessment(gap_config)
        check = next(
            c for a in report.articles for c in a.checks if c.check_id == "ART32B-002"
        )
        assert check.status in (ComplianceStatus.GAP, ComplianceStatus.PARTIAL)

    def test_backup_gap(self, gap_config):
        report = run_assessment(gap_config)
        check = next(
            c for a in report.articles for c in a.checks if c.check_id == "ART32C-001"
        )
        assert check.status == ComplianceStatus.GAP

    def test_siem_gap(self, gap_config):
        report = run_assessment(gap_config)
        check = next(
            c for a in report.articles for c in a.checks if c.check_id == "ART33-001"
        )
        assert check.status == ComplianceStatus.GAP


# ---------------------------------------------------------------------------
# Empty config — should surface PARTIAL (not-assessed) not crash
# ---------------------------------------------------------------------------

class TestEmptyConfig:
    def test_does_not_crash(self, empty_config):
        report = run_assessment(empty_config)
        assert report is not None

    def test_all_articles_present(self, empty_config):
        report = run_assessment(empty_config)
        assert len(report.articles) == 14

    def test_no_gaps_on_empty(self, empty_config):
        """Empty config = 'not assessed' = PARTIAL, not GAP."""
        report = run_assessment(empty_config)
        # Most checks should be PARTIAL (not assessed), not GAP
        all_checks = [c for a in report.articles for c in a.checks]
        gap_count = sum(1 for c in all_checks if c.status == ComplianceStatus.GAP)
        partial_count = sum(1 for c in all_checks if c.status == ComplianceStatus.PARTIAL)
        assert partial_count > gap_count


# ---------------------------------------------------------------------------
# Report serialisation
# ---------------------------------------------------------------------------

class TestReportSerialisation:
    def test_to_dict_has_required_keys(self, compliant_config):
        report = run_assessment(compliant_config)
        d = report.to_dict()
        assert "system_name" in d
        assert "overall_score" in d
        assert "overall_status" in d
        assert "config_confidence" in d
        assert "special_category_data" in d
        assert "articles" in d
        assert len(d["articles"]) == 14

    def test_config_confidence_range(self, compliant_config):
        report = run_assessment(compliant_config)
        assert 0.0 <= report.config_confidence <= 1.0

    def test_special_category_raises_threshold(self):
        from gdpr_mapper.models.config_input import SecurityConfig, SystemInfo
        cfg = SecurityConfig(system=SystemInfo(name="SCat", contains_special_category=True))
        report = run_assessment(cfg)
        assert report.special_category_data is True
        assert report._satisfied_threshold > 0.80

    def test_check_results_in_dict(self, compliant_config):
        report = run_assessment(compliant_config)
        d = report.to_dict()
        for art in d["articles"]:
            assert "checks" in art
            for chk in art["checks"]:
                assert "check_id" in chk
                assert "status" in chk
                assert "evidence" in chk
                assert "remediation" in chk

    def test_score_between_0_and_1(self, compliant_config):
        report = run_assessment(compliant_config)
        assert 0.0 <= report.overall_score <= 1.0
        for art in report.articles:
            assert 0.0 <= art.score <= 1.0


# ---------------------------------------------------------------------------
# Firewall-specific checks
# ---------------------------------------------------------------------------

class TestFirewallChecks:
    def test_ssh_internet_exposure_detected(self, gap_config):
        """SSH from 0.0.0.0/0 must trigger a PARTIAL or GAP on ART32B-002."""
        report = run_assessment(gap_config)
        check = next(c for a in report.articles for c in a.checks if c.check_id == "ART32B-002")
        assert check.status in (ComplianceStatus.GAP, ComplianceStatus.PARTIAL)

    def test_restricted_ssh_satisfied(self, compliant_config):
        """SSH from 10.0.0.0/8 only → management ports check should be SATISFIED."""
        report = run_assessment(compliant_config)
        check = next(c for a in report.articles for c in a.checks if c.check_id == "ART32B-002")
        assert check.status == ComplianceStatus.SATISFIED

    def test_default_deny_satisfied(self, compliant_config):
        report = run_assessment(compliant_config)
        check = next(c for a in report.articles for c in a.checks if c.check_id == "ART25-001")
        assert check.status == ComplianceStatus.SATISFIED

    def test_default_allow_gap(self, gap_config):
        report = run_assessment(gap_config)
        check = next(c for a in report.articles for c in a.checks if c.check_id == "ART25-001")
        assert check.status == ComplianceStatus.GAP
