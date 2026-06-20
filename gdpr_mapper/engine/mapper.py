"""Orchestrates checks against a SecurityConfig to produce a ComplianceReport."""

from __future__ import annotations
from datetime import datetime, timezone

from ..models.config_input import SecurityConfig
from ..models.compliance import ArticleResult, ComplianceReport
from .checks import ALL_CHECKS, CHECKS_BY_ARTICLE

ARTICLE_META: dict[str, tuple[str, str]] = {
    "Art.5(1)(f)": (
        "Integrity and Confidentiality",
        "Personal data must be processed in a manner that ensures appropriate security, including protection against unauthorised or unlawful processing and accidental loss, destruction or damage.",
    ),
    "Art.25": (
        "Data Protection by Design and by Default",
        "Technical and organisational measures must implement data protection principles and integrate necessary safeguards into processing, ensuring only necessary personal data is processed by default.",
    ),
    "Art.30": (
        "Records of Processing Activities",
        "Controllers must maintain records of processing activities including purposes, data categories, recipients, retention periods, and security measures.",
    ),
    "Art.32(1)(a)": (
        "Pseudonymisation and Encryption",
        "Implementation of pseudonymisation and encryption of personal data as appropriate technical measures.",
    ),
    "Art.32(1)(b)": (
        "Confidentiality, Integrity, Availability and Resilience",
        "The ability to ensure ongoing confidentiality, integrity, availability and resilience of processing systems and services.",
    ),
    "Art.32(1)(c)": (
        "Restore Availability After Incident",
        "The ability to restore availability and access to personal data in a timely manner following a physical or technical incident.",
    ),
    "Art.32(1)(d)": (
        "Regular Testing and Evaluation",
        "A process for regularly testing, assessing and evaluating the effectiveness of technical and organisational measures.",
    ),
    "Art.33": (
        "Notification of Breach to Supervisory Authority",
        "Personal data breaches must be notified to the supervisory authority (ICO in the UK) within 72 hours where feasible.",
    ),
    "Art.35": (
        "Data Protection Impact Assessment",
        "Where processing is likely to result in high risk, a DPIA must be carried out prior to processing.",
    ),
    "Art.44": (
        "General Principle for International Transfers",
        "Transfers of personal data to third countries may only take place with an adequate safeguard in place.",
    ),
    "Art.5(1)(b)": (
        "Purpose Limitation",
        "Personal data must be collected for specified, explicit and legitimate purposes and not further processed in a manner incompatible with those purposes.",
    ),
    "Art.5(1)(e)": (
        "Storage Limitation",
        "Personal data must be kept in a form which permits identification of data subjects for no longer than is necessary for the purposes for which it is processed.",
    ),
    "Art.13": (
        "Transparency — Information to be Provided",
        "Where personal data is collected directly from the data subject, the controller must provide information including the identity of the controller, purposes and lawful bases for processing, retention periods, and subject rights.",
    ),
    "Art.17": (
        "Right to Erasure ('Right to be Forgotten')",
        "Data subjects have the right to obtain erasure of their personal data without undue delay where one of the grounds in Art.17(1) applies, including where the data is no longer necessary for the purpose for which it was collected.",
    ),
}

ARTICLE_ORDER = list(ARTICLE_META.keys())


def run_assessment(config: SecurityConfig, config_source: str = "unknown") -> ComplianceReport:
    """Run all compliance checks against a SecurityConfig and return a report."""
    article_results: list[ArticleResult] = []

    for article_id in ARTICLE_ORDER:
        title, summary = ARTICLE_META[article_id]
        checks = CHECKS_BY_ARTICLE.get(article_id, [])
        results = [check.run(config) for check in checks]

        article_results.append(
            ArticleResult(
                article_id=article_id,
                article_title=title,
                article_summary=summary,
                checks=results,
            )
        )

    return ComplianceReport(
        system_name=config.system.name,
        system_description=config.system.description,
        generated_at=datetime.now(tz=timezone.utc),
        config_source=config_source,
        articles=article_results,
        special_category_data=config.system.contains_special_category,
    )
