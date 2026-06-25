"""Shared fixtures for the test suite."""

from __future__ import annotations
from pathlib import Path
import pytest

from gdpr_mapper.models.config_input import (
    SecurityConfig, SystemInfo, FirewallConfig, FirewallRule,
    EncryptionConfig, AtRestEncryption, InTransitEncryption, KeyRotation,
    AccessControlConfig, MFAConfig, PrivilegedAccessConfig, RBACConfig,
    AdminAccessConfig, LoggingConfig, AuditLoggingConfig, LogRetentionConfig,
    AlertingConfig, IncidentResponseConfig, DataProtectionConfig,
    BackupConfig, VulnerabilityManagementConfig, ScanningConfig,
    PatchingConfig, PenTestConfig, DPIAConfig, InternationalTransfersConfig,
    DataResidencyConfig, ThirdPartyProcessorsConfig,
    PrivacyConfig, DataRetentionConfig, ErasureRequestConfig,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
DATA_DIR = Path(__file__).parent.parent / "data" / "sample_configs"


def _make_compliant_config() -> SecurityConfig:
    return SecurityConfig(
        system=SystemInfo(name="Test System", environment="production",
                          data_classification="personal"),
        firewall=FirewallConfig(
            default_ingress="deny",
            network_segmentation=True,
            rules=[
                FirewallRule(name="HTTPS", port="443", source="0.0.0.0/0", action="allow", direction="inbound"),
                FirewallRule(name="SSH mgmt", port="22", source="10.0.0.0/8", action="allow", direction="inbound"),
            ],
        ),
        encryption=EncryptionConfig(
            at_rest=AtRestEncryption(enabled=True, algorithm="AES-256", key_management="hsm",
                                     covers=["database", "storage"]),
            in_transit=InTransitEncryption(tls_version="1.3", tls_12_minimum=True, hsts=True),
            key_rotation=KeyRotation(enabled=True, period_days=90),
        ),
        access_control=AccessControlConfig(
            mfa=MFAConfig(enabled=True, applies_to="all"),
            privileged_access=PrivilegedAccessConfig(pam_solution=True, just_in_time=True),
            rbac=RBACConfig(enabled=True, principle_least_privilege=True, regular_review=True),
            admin_access=AdminAccessConfig(wildcard_admin_restricted=True),
        ),
        logging=LoggingConfig(
            audit_logging=AuditLoggingConfig(
                enabled=True,
                covers=["authentication", "authorization", "data_access", "admin_actions"],
            ),
            retention=LogRetentionConfig(period_days=365, immutable=True),
            centralized=True,
            siem_integration=True,
            alerting=AlertingConfig(enabled=True, breach_detection_rules=True),
        ),
        incident_response=IncidentResponseConfig(
            plan_documented=True,
            breach_notification_72h=True,
            data_breach_register=True,
            dpo_contact_documented=True,
        ),
        data_protection=DataProtectionConfig(
            pseudonymisation=True,
            data_minimisation_enforced=True,
        ),
        backups=BackupConfig(
            enabled=True, frequency="daily", offsite=True, tested=True,
            test_frequency="quarterly", encrypted=True,
        ),
        vulnerability_management=VulnerabilityManagementConfig(
            scanning=ScanningConfig(enabled=True, frequency="weekly", last_scan="2026-06-01"),
            patching=PatchingConfig(policy_documented=True, critical_patch_sla_days=14),
            penetration_testing=PenTestConfig(conducted=True, frequency="annual",
                                              last_test="2026-01-15"),
        ),
        dpia=DPIAConfig(required=True, completed=True, dpo_sign_off=True,
                        review_schedule="annual"),
        international_transfers=InternationalTransfersConfig(
            transfers_to_third_countries=False,
            data_residency=DataResidencyConfig(region="UK", documented=True),
        ),
        third_party_processors=ThirdPartyProcessorsConfig(
            inventory_maintained=True, dpas_signed=True,
        ),
        privacy=PrivacyConfig(
            notice_published=True,
            notice_url="https://example.gov.uk/privacy",
            notice_last_updated="2026-01-10",
            lawful_bases_documented=True,
            purpose_limitation_enforced=True,
        ),
        data_retention=DataRetentionConfig(
            policy_documented=True,
            maximum_retention_defined=True,
            automated_deletion=True,
            deletion_audit_trail=True,
            erasure_requests=ErasureRequestConfig(
                process_documented=True,
                sla_days=25,
                verified_deletion=True,
                automated_processing=True,
            ),
        ),
    )


def _make_gap_config() -> SecurityConfig:
    return SecurityConfig(
        system=SystemInfo(name="Gap System", environment="production",
                          data_classification="personal"),
        firewall=FirewallConfig(
            default_ingress="allow",
            network_segmentation=False,
            rules=[
                FirewallRule(name="All open", port="*", source="0.0.0.0/0", action="allow", direction="inbound"),
                FirewallRule(name="RDP open", port="3389", source="0.0.0.0/0", action="allow", direction="inbound"),
                FirewallRule(name="SSH open", port="22", source="0.0.0.0/0", action="allow", direction="inbound"),
            ],
        ),
        encryption=EncryptionConfig(
            at_rest=AtRestEncryption(enabled=False),
            in_transit=InTransitEncryption(tls_12_minimum=False, tls_version="1.0"),
            key_rotation=KeyRotation(enabled=False),
        ),
        access_control=AccessControlConfig(
            mfa=MFAConfig(enabled=False, applies_to="none"),
            rbac=RBACConfig(enabled=False, principle_least_privilege=False),
            admin_access=AdminAccessConfig(wildcard_admin_restricted=False),
        ),
        logging=LoggingConfig(
            audit_logging=AuditLoggingConfig(enabled=False, covers=[]),
            retention=LogRetentionConfig(period_days=30),
            siem_integration=False,
            alerting=AlertingConfig(enabled=False, breach_detection_rules=False),
        ),
        incident_response=IncidentResponseConfig(
            plan_documented=False,
            breach_notification_72h=False,
            data_breach_register=False,
        ),
        backups=BackupConfig(enabled=False),
        vulnerability_management=VulnerabilityManagementConfig(
            scanning=ScanningConfig(enabled=False),
            patching=PatchingConfig(policy_documented=False, critical_patch_sla_days=180),
            penetration_testing=PenTestConfig(conducted=False),
        ),
        dpia=DPIAConfig(required=True, completed=False),
        privacy=PrivacyConfig(
            notice_published=False,
            lawful_bases_documented=False,
            purpose_limitation_enforced=False,
        ),
        data_retention=DataRetentionConfig(
            policy_documented=False,
            maximum_retention_defined=False,
            automated_deletion=False,
            deletion_audit_trail=False,
            erasure_requests=ErasureRequestConfig(
                process_documented=False,
                sla_days=180,
                verified_deletion=False,
                automated_processing=False,
            ),
        ),
    )


@pytest.fixture
def compliant_config() -> SecurityConfig:
    return _make_compliant_config()


@pytest.fixture
def gap_config() -> SecurityConfig:
    return _make_gap_config()


@pytest.fixture
def empty_config() -> SecurityConfig:
    return SecurityConfig()
