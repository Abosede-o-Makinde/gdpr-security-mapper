"""Pydantic models for the unified security configuration input schema."""

from __future__ import annotations
from typing import Literal, Optional
from pydantic import BaseModel, Field


class SystemInfo(BaseModel):
    name: str = "Unnamed System"
    description: str = ""
    environment: Literal["production", "staging", "development", "unknown"] = "unknown"
    data_classification: Literal["personal", "sensitive", "public", "unknown"] = "unknown"
    contains_special_category: bool = False
    data_subjects_count: Optional[int] = None
    processing_activities: list[str] = Field(default_factory=list)


class FirewallRule(BaseModel):
    name: str = ""
    protocol: str = "*"
    port: str = "*"
    source: str = "*"
    destination: str = "*"
    action: Literal["allow", "deny"] = "allow"
    direction: Literal["inbound", "outbound"] = "inbound"


class FirewallConfig(BaseModel):
    default_ingress: Literal["deny", "allow", "unknown"] = "unknown"
    default_egress: Literal["deny", "allow", "unknown"] = "unknown"
    rules: list[FirewallRule] = Field(default_factory=list)
    network_segmentation: Optional[bool] = None
    zones: list[str] = Field(default_factory=list)


class AtRestEncryption(BaseModel):
    enabled: Optional[bool] = None
    algorithm: Optional[str] = None
    key_management: Optional[Literal["manual", "managed", "hsm"]] = None
    covers: list[str] = Field(default_factory=list)


class InTransitEncryption(BaseModel):
    tls_version: Optional[str] = None
    tls_12_minimum: Optional[bool] = None
    hsts: Optional[bool] = None
    certificate_valid: Optional[bool] = None
    internal_tls: Optional[bool] = None


class KeyRotation(BaseModel):
    enabled: Optional[bool] = None
    period_days: Optional[int] = None


class EncryptionConfig(BaseModel):
    at_rest: AtRestEncryption = Field(default_factory=AtRestEncryption)
    in_transit: InTransitEncryption = Field(default_factory=InTransitEncryption)
    key_rotation: KeyRotation = Field(default_factory=KeyRotation)


class MFAConfig(BaseModel):
    enabled: Optional[bool] = None
    applies_to: Optional[Literal["all", "privileged", "none"]] = None


class PrivilegedAccessConfig(BaseModel):
    pam_solution: Optional[bool] = None
    just_in_time: Optional[bool] = None
    break_glass_documented: Optional[bool] = None


class RBACConfig(BaseModel):
    enabled: Optional[bool] = None
    principle_least_privilege: Optional[bool] = None
    regular_review: Optional[bool] = None
    review_frequency_days: Optional[int] = None


class ServiceAccountConfig(BaseModel):
    inventory_maintained: Optional[bool] = None
    no_interactive_login: Optional[bool] = None
    secrets_managed: Optional[bool] = None


class AdminAccessConfig(BaseModel):
    wildcard_admin_restricted: Optional[bool] = None
    default_admin_disabled: Optional[bool] = None


class AccessControlConfig(BaseModel):
    mfa: MFAConfig = Field(default_factory=MFAConfig)
    privileged_access: PrivilegedAccessConfig = Field(default_factory=PrivilegedAccessConfig)
    rbac: RBACConfig = Field(default_factory=RBACConfig)
    service_accounts: ServiceAccountConfig = Field(default_factory=ServiceAccountConfig)
    admin_access: AdminAccessConfig = Field(default_factory=AdminAccessConfig)


class AuditLoggingConfig(BaseModel):
    enabled: Optional[bool] = None
    covers: list[str] = Field(default_factory=list)


class LogRetentionConfig(BaseModel):
    period_days: Optional[int] = None
    immutable: Optional[bool] = None


class AlertingConfig(BaseModel):
    enabled: Optional[bool] = None
    breach_detection_rules: Optional[bool] = None
    anomaly_detection: Optional[bool] = None


class LoggingConfig(BaseModel):
    audit_logging: AuditLoggingConfig = Field(default_factory=AuditLoggingConfig)
    retention: LogRetentionConfig = Field(default_factory=LogRetentionConfig)
    centralized: Optional[bool] = None
    siem_integration: Optional[bool] = None
    alerting: AlertingConfig = Field(default_factory=AlertingConfig)


class IncidentResponseConfig(BaseModel):
    plan_documented: Optional[bool] = None
    last_tested: Optional[str] = None
    breach_notification_72h: Optional[bool] = None
    data_breach_register: Optional[bool] = None
    dpo_contact_documented: Optional[bool] = None


class DataProtectionConfig(BaseModel):
    pseudonymisation: Optional[bool] = None
    anonymisation: Optional[bool] = None
    data_minimisation_enforced: Optional[bool] = None
    retention_policy_documented: Optional[bool] = None
    deletion_capability: Optional[bool] = None


class BackupConfig(BaseModel):
    enabled: Optional[bool] = None
    frequency: Optional[Literal["hourly", "daily", "weekly", "monthly"]] = None
    offsite: Optional[bool] = None
    tested: Optional[bool] = None
    test_frequency: Optional[str] = None
    encrypted: Optional[bool] = None


class ScanningConfig(BaseModel):
    enabled: Optional[bool] = None
    frequency: Optional[Literal["daily", "weekly", "monthly", "quarterly", "annual"]] = None
    last_scan: Optional[str] = None


class PatchingConfig(BaseModel):
    policy_documented: Optional[bool] = None
    critical_patch_sla_days: Optional[int] = None


class PenTestConfig(BaseModel):
    conducted: Optional[bool] = None
    frequency: Optional[str] = None
    last_test: Optional[str] = None


class VulnerabilityManagementConfig(BaseModel):
    scanning: ScanningConfig = Field(default_factory=ScanningConfig)
    patching: PatchingConfig = Field(default_factory=PatchingConfig)
    penetration_testing: PenTestConfig = Field(default_factory=PenTestConfig)


class DPIAConfig(BaseModel):
    required: Optional[bool] = None
    completed: Optional[bool] = None
    completion_date: Optional[str] = None
    dpo_sign_off: Optional[bool] = None
    review_schedule: Optional[str] = None


class TransferMechanism(BaseModel):
    type: str = ""
    countries: list[str] = Field(default_factory=list)


class DataResidencyConfig(BaseModel):
    region: Optional[str] = None
    documented: Optional[bool] = None


class InternationalTransfersConfig(BaseModel):
    transfers_to_third_countries: Optional[bool] = None
    transfer_mechanisms: list[TransferMechanism] = Field(default_factory=list)
    data_residency: DataResidencyConfig = Field(default_factory=DataResidencyConfig)


class ThirdPartyProcessorsConfig(BaseModel):
    inventory_maintained: Optional[bool] = None
    dpas_signed: Optional[bool] = None
    regular_review: Optional[bool] = None


class PrivacyConfig(BaseModel):
    """Art.13/14 transparency — privacy notice and lawful basis documentation."""

    notice_published: Optional[bool] = None
    notice_url: Optional[str] = None
    notice_last_updated: Optional[str] = None   # ISO date string
    lawful_bases_documented: Optional[bool] = None
    purpose_limitation_enforced: Optional[bool] = None
    cookie_consent_mechanism: Optional[bool] = None
    subject_rights_process_documented: Optional[bool] = None


class ErasureRequestConfig(BaseModel):
    """Art.17 — erasure request handling."""

    process_documented: Optional[bool] = None
    sla_days: Optional[int] = None              # UK GDPR: 1 calendar month (~30 days)
    verified_deletion: Optional[bool] = None    # deletion confirmed and audited
    automated_processing: Optional[bool] = None  # erasure partially or fully automated


class DataRetentionConfig(BaseModel):
    """Art.5(1)(e) storage limitation — retention periods and automated deletion."""

    policy_documented: Optional[bool] = None
    maximum_retention_defined: Optional[bool] = None   # per-category max retention set
    automated_deletion: Optional[bool] = None          # records deleted automatically at end of retention
    deletion_audit_trail: Optional[bool] = None        # audit log of what was deleted
    erasure_requests: ErasureRequestConfig = Field(default_factory=ErasureRequestConfig)


class SecurityConfig(BaseModel):
    """Root model for a system's unified security configuration."""

    system: SystemInfo = Field(default_factory=SystemInfo)
    firewall: FirewallConfig = Field(default_factory=FirewallConfig)
    encryption: EncryptionConfig = Field(default_factory=EncryptionConfig)
    access_control: AccessControlConfig = Field(default_factory=AccessControlConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    incident_response: IncidentResponseConfig = Field(default_factory=IncidentResponseConfig)
    data_protection: DataProtectionConfig = Field(default_factory=DataProtectionConfig)
    backups: BackupConfig = Field(default_factory=BackupConfig)
    vulnerability_management: VulnerabilityManagementConfig = Field(
        default_factory=VulnerabilityManagementConfig
    )
    dpia: DPIAConfig = Field(default_factory=DPIAConfig)
    international_transfers: InternationalTransfersConfig = Field(
        default_factory=InternationalTransfersConfig
    )
    third_party_processors: ThirdPartyProcessorsConfig = Field(
        default_factory=ThirdPartyProcessorsConfig
    )
    privacy: PrivacyConfig = Field(default_factory=PrivacyConfig)
    data_retention: DataRetentionConfig = Field(default_factory=DataRetentionConfig)
