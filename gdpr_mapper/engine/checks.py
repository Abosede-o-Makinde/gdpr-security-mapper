"""
All GDPR compliance checks.

Each Check evaluates one control against a SecurityConfig and returns a
(ComplianceStatus, evidence, finding) triple. The mapper runs every check
and aggregates results into ArticleResult objects.

Articles covered:
  Art.5(1)(f)   — Integrity and Confidentiality
  Art.25        — Data Protection by Design and Default
  Art.30        — Records of Processing Activities
  Art.32(1)(a)  — Pseudonymisation and Encryption
  Art.32(1)(b)  — Confidentiality, Integrity, Availability, Resilience
  Art.32(1)(c)  — Restore Availability After Incident
  Art.32(1)(d)  — Regular Testing and Evaluation
  Art.33        — Notification of Breach to Supervisory Authority
  Art.35        — Data Protection Impact Assessment
  Art.44        — General Principle for International Transfers
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Callable

from ..models.config_input import SecurityConfig
from ..models.compliance import ComplianceStatus, CheckResult, Severity

CheckFn = Callable[[SecurityConfig], tuple[ComplianceStatus, str, str]]

_NOT_ASSESSED = "Not assessed"

_RISKY_PORTS = {22, 23, 3389, 5985, 5986, 3306, 5432, 1433, 27017, 6379, 9200, 2375, 2376}
_OPEN_SOURCES = {"0.0.0.0/0", "::/0", "*", "Any", "Internet"}
_STRONG_ALGORITHMS = {"AES-256", "AES-128", "AES256", "AES128"}
_ADEQUATE_SCAN_FREQ = {"daily", "weekly"}


@dataclass
class Check:
    id: str
    article_id: str
    name: str
    description: str
    severity: Severity
    weight: float
    remediation: str
    evaluate: CheckFn

    def run(self, config: SecurityConfig) -> CheckResult:
        status, evidence, finding = self.evaluate(config)
        return CheckResult(
            check_id=self.id,
            article_id=self.article_id,
            control_name=self.name,
            description=self.description,
            status=status,
            evidence=evidence,
            finding=finding,
            remediation=self.remediation,
            severity=self.severity,
            weight=self.weight,
        )


# ---------------------------------------------------------------------------
# Art.5(1)(f) — Integrity and Confidentiality
# ---------------------------------------------------------------------------

def _check_art5_at_rest(cfg: SecurityConfig):
    enc = cfg.encryption.at_rest
    if enc.enabled is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "At-rest encryption status not declared in config."
    if enc.enabled:
        alg = enc.algorithm or "unspecified"
        return ComplianceStatus.SATISFIED, f"At-rest encryption enabled ({alg})", ""
    return ComplianceStatus.GAP, "At-rest encryption disabled", "Personal data is not encrypted at rest."


def _check_art5_tls(cfg: SecurityConfig):
    tr = cfg.encryption.in_transit
    if tr.tls_12_minimum is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "TLS minimum version not declared."
    if tr.tls_12_minimum:
        ver = tr.tls_version or "1.2+"
        return ComplianceStatus.SATISFIED, f"TLS {ver} enforced", ""
    return ComplianceStatus.GAP, "TLS 1.2 minimum not enforced", "Weak transport encryption permits downgrade attacks."


def _check_art5_mfa(cfg: SecurityConfig):
    mfa = cfg.access_control.mfa
    if mfa.enabled is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "MFA configuration not declared."
    if not mfa.enabled:
        return ComplianceStatus.GAP, "MFA disabled", "Without MFA, credential compromise directly enables unauthorised access to personal data."
    scope = mfa.applies_to or "unknown"
    if scope == "all":
        return ComplianceStatus.SATISFIED, "MFA enabled for all users", ""
    if scope == "privileged":
        return ComplianceStatus.PARTIAL, "MFA enabled for privileged users only", "MFA should cover all users with access to personal data, not just privileged accounts."
    return ComplianceStatus.PARTIAL, f"MFA scope: {scope}", "Review MFA scope — all accounts accessing personal data must be protected."


def _check_art5_audit_logging(cfg: SecurityConfig):
    al = cfg.logging.audit_logging
    if al.enabled is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Audit logging configuration not declared."
    if not al.enabled:
        return ComplianceStatus.GAP, "Audit logging disabled", "Without audit logs, unauthorised access to personal data cannot be detected or evidenced."
    covers = al.covers or []
    if {"authentication", "data_access"}.issubset(set(covers)):
        return ComplianceStatus.SATISFIED, f"Audit logging enabled, covering: {', '.join(covers)}", ""
    return ComplianceStatus.PARTIAL, f"Audit logging enabled but covers only: {', '.join(covers) or 'unspecified'}", "Ensure authentication events, data access, and admin actions are all logged."


def _check_art5_rbac(cfg: SecurityConfig):
    rbac = cfg.access_control.rbac
    if rbac.enabled is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "RBAC configuration not declared."
    if rbac.enabled:
        return ComplianceStatus.SATISFIED, "RBAC enabled", ""
    return ComplianceStatus.GAP, "RBAC not enabled", "Without role-based access control, the principle of least privilege cannot be enforced."


# ---------------------------------------------------------------------------
# Art.25 — Data Protection by Design and Default
# ---------------------------------------------------------------------------

def _check_art25_default_deny(cfg: SecurityConfig):
    di = cfg.firewall.default_ingress
    if di == "unknown":
        return ComplianceStatus.PARTIAL, "Default ingress posture not declared", "Cannot confirm privacy-by-default network posture."
    if di == "deny":
        return ComplianceStatus.SATISFIED, "Default deny ingress enforced", ""
    return ComplianceStatus.GAP, "Default allow ingress posture", "A default-allow firewall violates privacy-by-design — all traffic should be denied unless explicitly permitted."


def _check_art25_least_privilege(cfg: SecurityConfig):
    rbac = cfg.access_control.rbac
    if rbac.principle_least_privilege is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Least privilege posture not declared."
    if rbac.principle_least_privilege:
        return ComplianceStatus.SATISFIED, "Principle of least privilege enforced", ""
    return ComplianceStatus.GAP, "Least privilege not enforced", "Data Protection by Design requires minimal access to personal data by default."


def _check_art25_data_minimisation(cfg: SecurityConfig):
    dp = cfg.data_protection
    if dp.data_minimisation_enforced is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Data minimisation controls not declared."
    if dp.data_minimisation_enforced:
        return ComplianceStatus.SATISFIED, "Data minimisation enforced", ""
    return ComplianceStatus.GAP, "Data minimisation not enforced", "Art.25(2) requires only data strictly necessary for the specific purpose to be processed by default."


def _check_art25_pseudonymisation(cfg: SecurityConfig):
    dp = cfg.data_protection
    if dp.pseudonymisation is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Pseudonymisation configuration not declared."
    if dp.pseudonymisation:
        return ComplianceStatus.SATISFIED, "Pseudonymisation implemented", ""
    return ComplianceStatus.PARTIAL, "Pseudonymisation not implemented", "Pseudonymisation is recommended by Art.25 as a privacy-by-design measure. Consider tokenising identifiers."


def _check_art25_mfa_all(cfg: SecurityConfig):
    mfa = cfg.access_control.mfa
    if mfa.enabled is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "MFA scope not declared."
    if mfa.enabled and mfa.applies_to == "all":
        return ComplianceStatus.SATISFIED, "MFA enforced for all users", ""
    if mfa.enabled:
        return ComplianceStatus.PARTIAL, f"MFA scope is '{mfa.applies_to}', not 'all'", "Privacy by default requires MFA for every account with access to personal data."
    return ComplianceStatus.GAP, "MFA not enabled", "All access to systems processing personal data should require MFA."


# ---------------------------------------------------------------------------
# Art.30 — Records of Processing Activities
# ---------------------------------------------------------------------------

def _check_art30_auth_events(cfg: SecurityConfig):
    covers = cfg.logging.audit_logging.covers or []
    if cfg.logging.audit_logging.enabled is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Logging coverage not declared."
    if "authentication" in covers:
        return ComplianceStatus.SATISFIED, "Authentication events logged", ""
    return ComplianceStatus.GAP, "Authentication events not logged", "Authentication event logs are foundational records of who accessed systems processing personal data."


def _check_art30_data_access(cfg: SecurityConfig):
    covers = cfg.logging.audit_logging.covers or []
    if cfg.logging.audit_logging.enabled is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Logging coverage not declared."
    if "data_access" in covers:
        return ComplianceStatus.SATISFIED, "Data access events logged", ""
    return ComplianceStatus.GAP, "Data access events not logged", "Art.30 records must evidence who accessed personal data and when — requires data access logging."


def _check_art30_retention(cfg: SecurityConfig):
    days = cfg.logging.retention.period_days
    if days is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Log retention period not declared."
    if days >= 365:
        return ComplianceStatus.SATISFIED, f"Log retention: {days} days", ""
    if days >= 180:
        return ComplianceStatus.PARTIAL, f"Log retention: {days} days", "Retention of 180 days is borderline — 365 days is recommended to support breach investigations and ICO inquiries."
    return ComplianceStatus.GAP, f"Log retention only {days} days", "Logs must be retained long enough to evidence compliance. Minimum 180 days; 365+ recommended."


def _check_art30_centralised(cfg: SecurityConfig):
    if cfg.logging.centralized is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Centralised logging not declared."
    if cfg.logging.centralized:
        return ComplianceStatus.SATISFIED, "Centralised logging enabled", ""
    return ComplianceStatus.PARTIAL, "Logs not centralised", "Distributed logs are harder to query for subject access requests and breach investigations. Centralise into a SIEM."


def _check_art30_processor_inventory(cfg: SecurityConfig):
    inv = cfg.third_party_processors.inventory_maintained
    if inv is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Third-party processor inventory status not declared."
    if inv:
        dpas = cfg.third_party_processors.dpas_signed
        if dpas:
            return ComplianceStatus.SATISFIED, "Processor inventory maintained and DPAs signed", ""
        return ComplianceStatus.PARTIAL, "Processor inventory exists but DPA status unconfirmed", "Art.28 requires a signed Data Processing Agreement with each processor."
    return ComplianceStatus.GAP, "No processor inventory", "Art.30(2) requires controllers to maintain records of all processors. Build an inventory with DPA references."


# ---------------------------------------------------------------------------
# Art.32(1)(a) — Pseudonymisation and Encryption
# ---------------------------------------------------------------------------

def _check_32a_at_rest_enabled(cfg: SecurityConfig):
    return _check_art5_at_rest(cfg)  # same check, reused


def _check_32a_strong_algorithm(cfg: SecurityConfig):
    enc = cfg.encryption.at_rest
    if enc.enabled is None or not enc.enabled:
        return ComplianceStatus.NA, "At-rest encryption not enabled", ""
    alg = (enc.algorithm or "").upper().replace("-", "")
    if alg.replace("_", "") in {a.replace("-", "") for a in _STRONG_ALGORITHMS}:
        return ComplianceStatus.SATISFIED, f"Strong algorithm in use: {enc.algorithm}", ""
    if alg:
        return ComplianceStatus.PARTIAL, f"Algorithm '{enc.algorithm}' — verify it meets AES-256 equivalent strength", "Weak or deprecated algorithms (e.g. DES, 3DES, RC4) must not be used for personal data."
    return ComplianceStatus.PARTIAL, "Algorithm not specified", "Declare the encryption algorithm in use to evidence Art.32(1)(a) compliance."


def _check_32a_tls(cfg: SecurityConfig):
    return _check_art5_tls(cfg)


def _check_32a_tls13(cfg: SecurityConfig):
    tr = cfg.encryption.in_transit
    if tr.tls_version is None:
        return ComplianceStatus.PARTIAL, "TLS version not declared", "Declare TLS version in use."
    if tr.tls_version.startswith("1.3"):
        return ComplianceStatus.SATISFIED, "TLS 1.3 in use (best practice)", ""
    return ComplianceStatus.PARTIAL, f"TLS {tr.tls_version} in use — TLS 1.3 preferred", "TLS 1.3 removes weak cipher suites present in 1.2 and should be preferred for new deployments."


def _check_32a_key_rotation(cfg: SecurityConfig):
    kr = cfg.encryption.key_rotation
    if kr.enabled is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Key rotation configuration not declared."
    if not kr.enabled:
        return ComplianceStatus.GAP, "Key rotation disabled", "Static encryption keys increase exposure window if compromised. Rotate keys regularly (≤90 days for sensitive data)."
    period = kr.period_days
    if period and period <= 90:
        return ComplianceStatus.SATISFIED, f"Key rotation enabled, period: {period} days", ""
    return ComplianceStatus.PARTIAL, f"Key rotation enabled, period: {period or 'unspecified'} days", "Key rotation period should be ≤90 days for personal data."


def _check_32a_pseudonymisation(cfg: SecurityConfig):
    return _check_art25_pseudonymisation(cfg)


# ---------------------------------------------------------------------------
# Art.32(1)(b) — Confidentiality, Integrity, Availability, Resilience
# ---------------------------------------------------------------------------

def _check_32b_default_deny(cfg: SecurityConfig):
    return _check_art25_default_deny(cfg)


def _check_32b_management_ports(cfg: SecurityConfig):
    rules = cfg.firewall.rules
    if not rules:
        return ComplianceStatus.PARTIAL, "No firewall rules declared", "Cannot assess management port exposure."

    exposed = []
    for r in rules:
        if r.direction != "inbound" or r.action != "allow":
            continue
        if r.source not in _OPEN_SOURCES:
            continue
        try:
            port_int = int(r.port)
        except (ValueError, TypeError):
            if r.port == "*":
                exposed.append(f"ALL ({r.source})")
            continue
        if port_int in _RISKY_PORTS:
            exposed.append(f"port {port_int} from {r.source}")

    if not exposed:
        return ComplianceStatus.SATISFIED, "No management ports open to internet", ""
    if len(exposed) <= 2:
        return ComplianceStatus.PARTIAL, f"Management ports exposed: {', '.join(exposed)}", "Restrict SSH/RDP/DB ports to known management IPs or a VPN/bastion host."
    return ComplianceStatus.GAP, f"{len(exposed)} management port(s) open to internet: {', '.join(exposed)}", "Critical exposure — management ports accessible from the internet create high-risk entry points for attackers."


def _check_32b_segmentation(cfg: SecurityConfig):
    seg = cfg.firewall.network_segmentation
    if seg is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Network segmentation not declared."
    if seg:
        zones = cfg.firewall.zones
        zone_info = f" (zones: {', '.join(zones)})" if zones else ""
        return ComplianceStatus.SATISFIED, f"Network segmentation in place{zone_info}", ""
    return ComplianceStatus.GAP, "No network segmentation", "Flat networks allow lateral movement — segment personal data processing into dedicated zones (DMZ, app, DB)."


def _check_32b_mfa(cfg: SecurityConfig):
    return _check_art5_mfa(cfg)


def _check_32b_pam(cfg: SecurityConfig):
    pa = cfg.access_control.privileged_access
    if pa.pam_solution is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "PAM solution status not declared."
    if pa.pam_solution:
        jit = pa.just_in_time
        jit_str = " with JIT access" if jit else ""
        return ComplianceStatus.SATISFIED, f"PAM solution deployed{jit_str}", ""
    return ComplianceStatus.PARTIAL, "No PAM solution deployed", "Privileged access management controls are key to restricting standing admin access to personal data stores."


def _check_32b_wildcard_admin(cfg: SecurityConfig):
    aa = cfg.access_control.admin_access
    if aa.wildcard_admin_restricted is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Wildcard admin access policy not declared."
    if aa.wildcard_admin_restricted:
        return ComplianceStatus.SATISFIED, "Wildcard admin access restricted", ""
    return ComplianceStatus.GAP, "Wildcard admin access not restricted", "Wildcard administrative roles (e.g. * / Owner / Global Admin) should be eliminated in favour of scoped roles."


# ---------------------------------------------------------------------------
# Art.32(1)(c) — Restore Availability After Incident
# ---------------------------------------------------------------------------

def _check_32c_backups_enabled(cfg: SecurityConfig):
    bk = cfg.backups
    if bk.enabled is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Backup status not declared."
    if bk.enabled:
        return ComplianceStatus.SATISFIED, "Backups enabled", ""
    return ComplianceStatus.GAP, "Backups not enabled", "Art.32(1)(c) requires the ability to restore personal data availability — backups are essential."


def _check_32c_backup_frequency(cfg: SecurityConfig):
    bk = cfg.backups
    if bk.enabled is False:
        return ComplianceStatus.NA, "Backups disabled", ""
    if bk.frequency is None:
        return ComplianceStatus.PARTIAL, "Backup frequency not declared", "Declare backup frequency to evidence restoration capability."
    if bk.frequency in {"hourly", "daily"}:
        return ComplianceStatus.SATISFIED, f"Backup frequency: {bk.frequency}", ""
    return ComplianceStatus.PARTIAL, f"Backup frequency: {bk.frequency}", "Weekly or less frequent backups create large recovery windows — daily is recommended for personal data."


def _check_32c_offsite(cfg: SecurityConfig):
    bk = cfg.backups
    if bk.enabled is False:
        return ComplianceStatus.NA, "Backups disabled", ""
    if bk.offsite is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Offsite backup status not declared."
    if bk.offsite:
        return ComplianceStatus.SATISFIED, "Offsite backups configured", ""
    return ComplianceStatus.GAP, "No offsite backups", "On-site-only backups are lost in a physical incident. Store backups in a geographically separate location."


def _check_32c_backup_tested(cfg: SecurityConfig):
    bk = cfg.backups
    if bk.enabled is False:
        return ComplianceStatus.NA, "Backups disabled", ""
    if bk.tested is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Backup test status not declared."
    if bk.tested:
        freq = bk.test_frequency or "unspecified frequency"
        return ComplianceStatus.SATISFIED, f"Backups tested ({freq})", ""
    return ComplianceStatus.GAP, "Backups never tested", "Untested backups are unreliable. Run restoration tests at least quarterly — an untested backup is not a backup."


def _check_32c_backup_encrypted(cfg: SecurityConfig):
    bk = cfg.backups
    if bk.enabled is False:
        return ComplianceStatus.NA, "Backups disabled", ""
    if bk.encrypted is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Backup encryption status not declared."
    if bk.encrypted:
        return ComplianceStatus.SATISFIED, "Backups encrypted", ""
    return ComplianceStatus.GAP, "Backups not encrypted", "Unencrypted backups constitute a personal data exposure risk — encrypt backups using AES-256."


# ---------------------------------------------------------------------------
# Art.32(1)(d) — Regular Testing, Assessing and Evaluating
# ---------------------------------------------------------------------------

def _check_32d_scanning(cfg: SecurityConfig):
    sc = cfg.vulnerability_management.scanning
    if sc.enabled is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Vulnerability scanning status not declared."
    if sc.enabled:
        last = sc.last_scan or "date unknown"
        return ComplianceStatus.SATISFIED, f"Vulnerability scanning enabled (last scan: {last})", ""
    return ComplianceStatus.GAP, "Vulnerability scanning disabled", "Regular vulnerability scanning is required to detect weaknesses that could expose personal data."


def _check_32d_scan_frequency(cfg: SecurityConfig):
    sc = cfg.vulnerability_management.scanning
    if sc.enabled is False:
        return ComplianceStatus.NA, "Scanning disabled", ""
    if sc.frequency is None:
        return ComplianceStatus.PARTIAL, "Scan frequency not declared", "Declare how frequently vulnerability scans run."
    if sc.frequency in _ADEQUATE_SCAN_FREQ:
        return ComplianceStatus.SATISFIED, f"Scan frequency: {sc.frequency}", ""
    return ComplianceStatus.PARTIAL, f"Scan frequency: {sc.frequency}", "Monthly or less frequent scanning leaves long windows for undetected vulnerabilities — aim for weekly."


def _check_32d_patch_policy(cfg: SecurityConfig):
    pt = cfg.vulnerability_management.patching
    if pt.policy_documented is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Patch management policy status not declared."
    if pt.policy_documented:
        return ComplianceStatus.SATISFIED, "Patch management policy documented", ""
    return ComplianceStatus.GAP, "No patch management policy", "A documented patching policy is required to systematically remediate vulnerabilities in systems processing personal data."


def _check_32d_critical_patch_sla(cfg: SecurityConfig):
    pt = cfg.vulnerability_management.patching
    if pt.critical_patch_sla_days is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Critical patch SLA not declared."
    sla = pt.critical_patch_sla_days
    if sla <= 14:
        return ComplianceStatus.SATISFIED, f"Critical patch SLA: {sla} days", ""
    if sla <= 30:
        return ComplianceStatus.PARTIAL, f"Critical patch SLA: {sla} days", "A 30-day SLA for critical patches is the maximum acceptable — target ≤14 days."
    return ComplianceStatus.GAP, f"Critical patch SLA: {sla} days", "SLAs over 30 days for critical patches are unacceptable for systems holding personal data."


def _check_32d_pentest(cfg: SecurityConfig):
    pt = cfg.vulnerability_management.penetration_testing
    if pt.conducted is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Penetration testing status not declared."
    if pt.conducted:
        last = pt.last_test or "date unknown"
        freq = pt.frequency or "frequency unspecified"
        return ComplianceStatus.SATISFIED, f"Penetration testing conducted (last: {last}, {freq})", ""
    return ComplianceStatus.GAP, "No penetration testing conducted", "Annual penetration testing is required to evaluate the effectiveness of security controls protecting personal data."


# ---------------------------------------------------------------------------
# Art.33 — Notification of Breach to Supervisory Authority
# ---------------------------------------------------------------------------

def _check_33_siem(cfg: SecurityConfig):
    if cfg.logging.siem_integration is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "SIEM integration status not declared."
    if cfg.logging.siem_integration:
        return ComplianceStatus.SATISFIED, "SIEM integration active", ""
    return ComplianceStatus.GAP, "No SIEM integration", "Without a SIEM, breach detection relies on manual log review — unacceptable for the 72-hour notification requirement."


def _check_33_breach_rules(cfg: SecurityConfig):
    if cfg.logging.alerting.breach_detection_rules is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Breach detection rules not declared."
    if cfg.logging.alerting.breach_detection_rules:
        return ComplianceStatus.SATISFIED, "Breach detection rules configured", ""
    return ComplianceStatus.GAP, "No breach detection rules", "Automated detection rules are needed to identify data breaches and trigger the 72-hour notification countdown."


def _check_33_72h_capability(cfg: SecurityConfig):
    ir = cfg.incident_response
    if ir.breach_notification_72h is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "72-hour notification capability not declared."
    if ir.breach_notification_72h:
        return ComplianceStatus.SATISFIED, "72-hour breach notification capability confirmed", ""
    return ComplianceStatus.GAP, "72-hour notification capability not confirmed", "Art.33(1) mandates notification to the ICO within 72 hours of becoming aware of a breach."


def _check_33_breach_register(cfg: SecurityConfig):
    ir = cfg.incident_response
    if ir.data_breach_register is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Data breach register status not declared."
    if ir.data_breach_register:
        return ComplianceStatus.SATISFIED, "Data breach register maintained", ""
    return ComplianceStatus.GAP, "No data breach register", "Art.33(5) requires all breaches to be documented, including those not reported to the ICO."


def _check_33_ir_plan(cfg: SecurityConfig):
    ir = cfg.incident_response
    if ir.plan_documented is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "IR plan status not declared."
    if ir.plan_documented:
        last = ir.last_tested or "untested"
        return ComplianceStatus.SATISFIED, f"IR plan documented (last tested: {last})", ""
    return ComplianceStatus.GAP, "No incident response plan", "Without a documented IR plan, the ability to coordinate a breach response within 72 hours is unreliable."


def _check_33_dpo_contact(cfg: SecurityConfig):
    ir = cfg.incident_response
    if ir.dpo_contact_documented is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "DPO contact status not declared."
    if ir.dpo_contact_documented:
        return ComplianceStatus.SATISFIED, "DPO contact documented and accessible", ""
    return ComplianceStatus.PARTIAL, "DPO contact not documented", "The DPO must be reachable in a breach scenario to advise on notification obligations. Document and communicate DPO contact details."


# ---------------------------------------------------------------------------
# Art.35 — Data Protection Impact Assessment
# ---------------------------------------------------------------------------

def _check_35_dpia_completed(cfg: SecurityConfig):
    dpia = cfg.dpia
    if dpia.required is None:
        return ComplianceStatus.PARTIAL, "DPIA requirement not assessed", "Determine whether a DPIA is required for this system's processing activities."
    if not dpia.required:
        return ComplianceStatus.SATISFIED, "DPIA not required for this processing", ""
    if dpia.completed:
        date = dpia.completion_date or "date not recorded"
        return ComplianceStatus.SATISFIED, f"DPIA completed ({date})", ""
    return ComplianceStatus.GAP, "DPIA required but not completed", "Art.35(1): high-risk processing must not begin without a completed DPIA."


def _check_35_dpo_signoff(cfg: SecurityConfig):
    dpia = cfg.dpia
    if dpia.required is False:
        return ComplianceStatus.NA, "DPIA not required", ""
    if dpia.completed is False:
        return ComplianceStatus.NA, "DPIA not yet completed", ""
    if dpia.dpo_sign_off is None:
        return ComplianceStatus.PARTIAL, "DPO sign-off status not declared", "Document whether the DPO has reviewed and signed off the DPIA."
    if dpia.dpo_sign_off:
        return ComplianceStatus.SATISFIED, "DPIA has DPO sign-off", ""
    return ComplianceStatus.PARTIAL, "DPIA completed but DPO sign-off missing", "The DPO must be consulted on the DPIA per Art.35(2)."


def _check_35_review_schedule(cfg: SecurityConfig):
    dpia = cfg.dpia
    if dpia.required is False:
        return ComplianceStatus.NA, "DPIA not required", ""
    if dpia.review_schedule:
        return ComplianceStatus.SATISFIED, f"DPIA review schedule: {dpia.review_schedule}", ""
    return ComplianceStatus.PARTIAL, "No DPIA review schedule defined", "DPIAs must be reviewed when the nature of processing changes, or on a regular schedule (recommend annual)."


# ---------------------------------------------------------------------------
# Art.44-49 — International Transfers
# ---------------------------------------------------------------------------

def _check_44_transfer_inventory(cfg: SecurityConfig):
    it = cfg.international_transfers
    if it.transfers_to_third_countries is None:
        return ComplianceStatus.PARTIAL, "Transfer activity not declared", "Document whether personal data is transferred outside the UK/EEA."
    if not it.transfers_to_third_countries:
        return ComplianceStatus.SATISFIED, "No transfers to third countries declared", ""
    mechanisms = it.transfer_mechanisms
    if mechanisms:
        types = ", ".join(m.type for m in mechanisms if m.type)
        return ComplianceStatus.SATISFIED, f"Transfer mechanisms documented: {types}", ""
    return ComplianceStatus.GAP, "International transfers occur but no mechanism documented", "Art.46 requires an appropriate safeguard (SCCs, BCRs, adequacy decision) for every third-country transfer."


def _check_44_adequacy_mechanism(cfg: SecurityConfig):
    it = cfg.international_transfers
    if it.transfers_to_third_countries is False:
        return ComplianceStatus.NA, "No international transfers", ""
    if it.transfers_to_third_countries is None:
        return ComplianceStatus.PARTIAL, "Transfer activity not declared", ""
    mechanisms = it.transfer_mechanisms
    valid_types = {"adequacy_decision", "standard_contractual_clauses", "sccs", "bcr", "binding_corporate_rules", "derogation"}
    if any(m.type.lower().replace(" ", "_") in valid_types for m in mechanisms):
        return ComplianceStatus.SATISFIED, "Valid transfer mechanism in place", ""
    if mechanisms:
        return ComplianceStatus.PARTIAL, f"Transfer mechanism declared but type unclear: {mechanisms[0].type}", "Confirm transfer mechanism is one of: adequacy decision, SCCs, BCRs, or Art.49 derogation."
    return ComplianceStatus.GAP, "No transfer mechanism documented", "Every transfer to a third country requires a documented lawful basis under Chapter V of UK GDPR."


def _check_44_data_residency(cfg: SecurityConfig):
    dr = cfg.international_transfers.data_residency
    if dr.documented is None:
        return ComplianceStatus.PARTIAL, "Data residency not declared", "Document where personal data is stored and processed."
    if dr.documented:
        region = dr.region or "region unspecified"
        return ComplianceStatus.SATISFIED, f"Data residency documented: {region}", ""
    return ComplianceStatus.PARTIAL, "Data residency not documented", "Documenting data residency supports subject access requests, transfer assessments, and breach notifications."


# ---------------------------------------------------------------------------
# Art.5(1)(b) — Purpose Limitation
# ---------------------------------------------------------------------------

def _check_plim_purposes_declared(cfg: SecurityConfig):
    activities = cfg.system.processing_activities
    if not activities:
        return ComplianceStatus.PARTIAL, "No processing activities declared", "Document all purposes for which personal data is processed — this underpins purpose limitation."
    return ComplianceStatus.SATISFIED, f"Processing activities declared: {', '.join(activities[:3])}{'...' if len(activities) > 3 else ''}", ""


def _check_plim_lawful_bases(cfg: SecurityConfig):
    pr = cfg.privacy
    if pr.lawful_bases_documented is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Confirm that a lawful basis has been identified and documented for each processing activity."
    if pr.lawful_bases_documented:
        return ComplianceStatus.SATISFIED, "Lawful bases documented for all processing activities", ""
    return ComplianceStatus.GAP, "Lawful bases not documented", "Art.6 requires a lawful basis for every processing activity. Document the basis (consent, contract, legal obligation, legitimate interests, etc.) and make it accessible."


def _check_plim_purpose_enforcement(cfg: SecurityConfig):
    pr = cfg.privacy
    if pr.purpose_limitation_enforced is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Confirm controls are in place to prevent data being used beyond its declared purpose."
    if pr.purpose_limitation_enforced:
        return ComplianceStatus.SATISFIED, "Technical controls enforce purpose limitation", ""
    return ComplianceStatus.PARTIAL, "Purpose limitation not technically enforced", "Implement access controls, data classification, and API-level restrictions to enforce purpose boundaries. Rely on technical controls, not just policy."


# ---------------------------------------------------------------------------
# Art.5(1)(e) — Storage Limitation
# ---------------------------------------------------------------------------

def _check_slim_retention_policy(cfg: SecurityConfig):
    dr = cfg.data_retention
    has_legacy = cfg.data_protection.retention_policy_documented
    documented = dr.policy_documented if dr.policy_documented is not None else has_legacy
    if documented is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Confirm a formal data retention policy exists."
    if documented:
        return ComplianceStatus.SATISFIED, "Data retention policy documented", ""
    return ComplianceStatus.GAP, "No data retention policy", "Art.5(1)(e) requires personal data to be kept no longer than necessary. Document maximum retention periods per data category."


def _check_slim_max_retention_defined(cfg: SecurityConfig):
    dr = cfg.data_retention
    if dr.maximum_retention_defined is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Confirm per-category maximum retention periods are defined."
    if dr.maximum_retention_defined:
        return ComplianceStatus.SATISFIED, "Per-category maximum retention periods defined", ""
    return ComplianceStatus.PARTIAL, "Maximum retention periods not defined per data category", "Define specific retention periods for each category of personal data (e.g. customer records: 7 years; marketing preferences: until withdrawal of consent)."


def _check_slim_automated_deletion(cfg: SecurityConfig):
    dr = cfg.data_retention
    has_legacy = cfg.data_protection.deletion_capability
    auto = dr.automated_deletion
    if auto is None and has_legacy is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Confirm whether automated deletion is in place at end of retention period."
    if auto:
        return ComplianceStatus.SATISFIED, "Automated deletion at end of retention period", ""
    if has_legacy:
        return ComplianceStatus.PARTIAL, "Deletion capability exists but not confirmed as automated", "Manual deletion processes are error-prone. Implement scheduled automated deletion jobs and log their output."
    return ComplianceStatus.GAP, "No automated deletion at end of retention period", "Personal data persisting beyond retention periods violates Art.5(1)(e). Implement automated deletion with an audit trail."


# ---------------------------------------------------------------------------
# Art.13/14 — Transparency (Privacy Notice)
# ---------------------------------------------------------------------------

def _check_trans_notice_published(cfg: SecurityConfig):
    pr = cfg.privacy
    if pr.notice_published is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Confirm a privacy notice is published and accessible."
    if not pr.notice_published:
        return ComplianceStatus.GAP, "Privacy notice not published", "Art.13/14 requires a privacy notice at the point of collection. Publish a notice covering: identity of controller, purposes, lawful bases, retention periods, and subject rights."
    url = pr.notice_url
    if url:
        return ComplianceStatus.SATISFIED, f"Privacy notice published ({url})", ""
    return ComplianceStatus.SATISFIED, "Privacy notice published (URL not recorded in config)", ""


def _check_trans_notice_current(cfg: SecurityConfig):
    pr = cfg.privacy
    if pr.notice_published is False:
        return ComplianceStatus.NA, "Privacy notice not published", ""
    if pr.notice_last_updated is None:
        return ComplianceStatus.PARTIAL, "Notice last-updated date not declared", "Record when the privacy notice was last reviewed and updated."
    try:
        from datetime import date
        updated = date.fromisoformat(pr.notice_last_updated)
        age_days = (date.today() - updated).days
        if age_days <= 365:
            return ComplianceStatus.SATISFIED, f"Privacy notice updated {age_days} days ago ({pr.notice_last_updated})", ""
        if age_days <= 730:
            return ComplianceStatus.PARTIAL, f"Privacy notice is {age_days} days old — review recommended", "Review the privacy notice annually or when processing activities change."
        return ComplianceStatus.GAP, f"Privacy notice is {age_days} days old — significantly out of date", "A notice over 2 years old is likely inaccurate. Review and update to reflect current processing activities and contact details."
    except (ValueError, TypeError):
        return ComplianceStatus.PARTIAL, f"Cannot parse notice date: {pr.notice_last_updated}", "Use ISO date format (YYYY-MM-DD) for notice_last_updated."


def _check_trans_lawful_bases_accessible(cfg: SecurityConfig):
    pr = cfg.privacy
    if pr.lawful_bases_documented is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Confirm lawful bases are documented and reflected in the privacy notice."
    if pr.lawful_bases_documented and pr.notice_published:
        return ComplianceStatus.SATISFIED, "Lawful bases documented and accessible via privacy notice", ""
    if pr.lawful_bases_documented:
        return ComplianceStatus.PARTIAL, "Lawful bases documented but notice not confirmed published", "Lawful bases must be communicated to data subjects via the privacy notice, not just held internally."
    return ComplianceStatus.GAP, "Lawful bases not documented or not accessible to data subjects", "Art.13(1)(c) requires the lawful basis to be communicated to data subjects at the time of collection."


# ---------------------------------------------------------------------------
# Art.17 — Right to Erasure ('Right to be Forgotten')
# ---------------------------------------------------------------------------

def _check_eras_process_documented(cfg: SecurityConfig):
    er = cfg.data_retention.erasure_requests
    has_legacy = cfg.data_protection.deletion_capability
    if er.process_documented is None and has_legacy is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Confirm a documented process exists for handling erasure requests."
    if er.process_documented:
        return ComplianceStatus.SATISFIED, "Erasure request process documented", ""
    if has_legacy:
        return ComplianceStatus.PARTIAL, "Deletion capability exists but erasure request process not formally documented", "Document the end-to-end process: how to receive requests, verification steps, which systems to delete from, and how to confirm deletion."
    return ComplianceStatus.GAP, "No erasure request process documented", "Art.17 grants data subjects the right to erasure. A documented, tested process is required to handle requests within 1 calendar month."


def _check_eras_sla(cfg: SecurityConfig):
    er = cfg.data_retention.erasure_requests
    if er.process_documented is False:
        return ComplianceStatus.NA, "Erasure process not documented", ""
    if er.sla_days is None:
        return ComplianceStatus.PARTIAL, "Erasure SLA not declared", "Define the SLA for responding to erasure requests. UK GDPR requires response within 1 calendar month (~30 days)."
    if er.sla_days <= 30:
        return ComplianceStatus.SATISFIED, f"Erasure SLA: {er.sla_days} days (within UK GDPR 1-month requirement)", ""
    if er.sla_days <= 90:
        return ComplianceStatus.PARTIAL, f"Erasure SLA: {er.sla_days} days — exceeds 1-month requirement without extension", "UK GDPR allows a 2-month extension for complex cases, but the default SLA must be 1 calendar month."
    return ComplianceStatus.GAP, f"Erasure SLA: {er.sla_days} days — far exceeds legal requirement", "Erasure requests must be completed within 1 calendar month. Overhaul the process to meet this requirement."


def _check_eras_verified_deletion(cfg: SecurityConfig):
    er = cfg.data_retention.erasure_requests
    if er.process_documented is False:
        return ComplianceStatus.NA, "Erasure process not documented", ""
    if er.verified_deletion is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Confirm whether deletion is verified and an audit trail maintained."
    if er.verified_deletion:
        return ComplianceStatus.SATISFIED, "Deletion verified with audit trail", ""
    return ComplianceStatus.PARTIAL, "Deletion not verified or audit trail absent", "Verification that data has been deleted (including from backups, archives, and downstream systems) is essential to evidence Art.17 compliance."


def _check_eras_technical_capability(cfg: SecurityConfig):
    dp = cfg.data_protection
    er = cfg.data_retention.erasure_requests
    has_capability = dp.deletion_capability
    has_automated = er.automated_processing
    if has_capability is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Confirm the technical capability to delete personal data on request exists."
    if has_capability and has_automated:
        return ComplianceStatus.SATISFIED, "Technical deletion capability confirmed, with automation", ""
    if has_capability:
        return ComplianceStatus.SATISFIED, "Technical deletion capability confirmed", ""
    return ComplianceStatus.GAP, "No technical deletion capability", "Without technical capability to delete personal data, Art.17 rights cannot be exercised. Review data architecture for immutable stores (e.g. append-only logs, immutable backups) and implement pseudonymisation or cryptographic erasure where full deletion is not possible."


# ---------------------------------------------------------------------------
# Article ID constants (used in the registry below)
# ---------------------------------------------------------------------------

_ART_5B = "Art.5(1)(b)"
_ART_5E = "Art.5(1)(e)"
_ART_13 = "Art.13"
_ART_17 = "Art.17"

# ---------------------------------------------------------------------------
# Check registry — all checks indexed by article
# ---------------------------------------------------------------------------

ALL_CHECKS: list[Check] = [
    # Art.5(1)(f)
    Check("ART5-001", "Art.5(1)(f)", "At-Rest Encryption",
          "Personal data is encrypted at rest.", Severity.CRITICAL, 1.5,
          "Enable AES-256 encryption for all datastores containing personal data.",
          _check_art5_at_rest),
    Check("ART5-002", "Art.5(1)(f)", "TLS Enforcement",
          "Data in transit is protected by TLS 1.2 or higher.", Severity.CRITICAL, 1.5,
          "Configure TLS 1.2 as the minimum version and disable all earlier protocols.",
          _check_art5_tls),
    Check("ART5-003", "Art.5(1)(f)", "Multi-Factor Authentication",
          "MFA is enforced to prevent unauthorised access.", Severity.HIGH, 1.2,
          "Enable MFA for all accounts with access to personal data. Use authenticator apps or hardware tokens, not SMS.",
          _check_art5_mfa),
    Check("ART5-004", "Art.5(1)(f)", "Audit Logging",
          "Security-relevant events are captured in audit logs.", Severity.HIGH, 1.2,
          "Enable audit logging covering authentication, data access, admin actions, and configuration changes.",
          _check_art5_audit_logging),
    Check("ART5-005", "Art.5(1)(f)", "Role-Based Access Control",
          "RBAC enforces least-privilege access to personal data.", Severity.HIGH, 1.0,
          "Implement RBAC with regular access reviews. Remove standing access to personal data where possible.",
          _check_art5_rbac),

    # Art.25
    Check("ART25-001", "Art.25", "Default Deny Firewall Posture",
          "Network ingress defaults to deny, permitting only explicitly needed traffic.", Severity.HIGH, 1.2,
          "Set default-deny on all network security groups and firewall policies. Permit only documented, business-required traffic.",
          _check_art25_default_deny),
    Check("ART25-002", "Art.25", "Principle of Least Privilege",
          "Access to personal data is restricted to the minimum necessary.", Severity.HIGH, 1.2,
          "Audit and remove over-privileged access. Use just-in-time access for admin operations.",
          _check_art25_least_privilege),
    Check("ART25-003", "Art.25", "Data Minimisation",
          "Only data strictly necessary for the stated purpose is collected and processed.", Severity.MEDIUM, 1.0,
          "Review data flows and remove collection of fields that are not strictly necessary. Enforce at application and schema level.",
          _check_art25_data_minimisation),
    Check("ART25-004", "Art.25", "Pseudonymisation",
          "Identifiers are pseudonymised where technically feasible.", Severity.MEDIUM, 0.8,
          "Tokenise or pseudonymise direct identifiers in databases and logs. Maintain the mapping key in a separate secure store.",
          _check_art25_pseudonymisation),
    Check("ART25-005", "Art.25", "Universal MFA Coverage",
          "MFA is enforced for all users, not only privileged accounts.", Severity.HIGH, 1.0,
          "Extend MFA policy to all user accounts — not just admins — as privacy-by-default requires universal protection.",
          _check_art25_mfa_all),

    # Art.30
    Check("ART30-001", "Art.30", "Authentication Event Logging",
          "All login/logout/failure events are recorded.", Severity.HIGH, 1.2,
          "Configure your SIEM/SIEM connector to capture authentication events from all identity providers and systems.",
          _check_art30_auth_events),
    Check("ART30-002", "Art.30", "Data Access Event Logging",
          "Access to personal data is recorded with user, timestamp, and resource.", Severity.HIGH, 1.2,
          "Enable database audit logging, object-level logging in cloud storage, and API access logs.",
          _check_art30_data_access),
    Check("ART30-003", "Art.30", "Log Retention Period",
          "Logs are retained for a period sufficient for breach investigation and ICO inquiry.", Severity.MEDIUM, 1.0,
          "Set log retention to at least 365 days. Use immutable (WORM) storage to prevent tampering.",
          _check_art30_retention),
    Check("ART30-004", "Art.30", "Centralised Logging",
          "Logs from all systems are aggregated into a central platform.", Severity.MEDIUM, 0.8,
          "Centralise logs into a SIEM (e.g. Microsoft Sentinel, Splunk, Elastic) to enable correlation and efficient querying.",
          _check_art30_centralised),
    Check("ART30-005", "Art.30", "Third-Party Processor Inventory",
          "All data processors are inventoried with DPAs in place.", Severity.HIGH, 1.0,
          "Build a processor inventory (name, purpose, data categories, country, DPA reference). Review annually.",
          _check_art30_processor_inventory),

    # Art.32(1)(a)
    Check("ART32A-001", "Art.32(1)(a)", "At-Rest Encryption",
          "Personal data at rest is encrypted.", Severity.CRITICAL, 1.5,
          "Enable AES-256 encryption across all storage services. Enable Transparent Data Encryption (TDE) on databases.",
          _check_32a_at_rest_enabled),
    Check("ART32A-002", "Art.32(1)(a)", "Encryption Algorithm Strength",
          "Encryption uses a strong, current algorithm (AES-256 or equivalent).", Severity.HIGH, 1.2,
          "Replace deprecated algorithms (DES, 3DES, RC4, MD5) with AES-256 or ChaCha20-Poly1305.",
          _check_32a_strong_algorithm),
    Check("ART32A-003", "Art.32(1)(a)", "TLS 1.2+ in Transit",
          "All data transfers use TLS 1.2 or higher.", Severity.CRITICAL, 1.5,
          "Disable TLS 1.0 and 1.1. Configure cipher suites to remove weak options (RC4, NULL, EXPORT, DES).",
          _check_32a_tls),
    Check("ART32A-004", "Art.32(1)(a)", "TLS 1.3 Preferred",
          "TLS 1.3 is used where possible to eliminate legacy cipher suites.", Severity.MEDIUM, 0.8,
          "Prefer TLS 1.3 on new deployments. It removes weak features present in TLS 1.2.",
          _check_32a_tls13),
    Check("ART32A-005", "Art.32(1)(a)", "Encryption Key Rotation",
          "Encryption keys are rotated on a regular schedule.", Severity.HIGH, 1.0,
          "Implement automated key rotation ≤90 days. Use managed key services (Azure Key Vault, AWS KMS) to simplify rotation.",
          _check_32a_key_rotation),
    Check("ART32A-006", "Art.32(1)(a)", "Pseudonymisation of Personal Data",
          "Personal identifiers are pseudonymised to reduce breach impact.", Severity.MEDIUM, 0.8,
          "Tokenise PII fields in databases and analytics pipelines. Store mapping keys in a separate, access-controlled system.",
          _check_32a_pseudonymisation),

    # Art.32(1)(b)
    Check("ART32B-001", "Art.32(1)(b)", "Default Deny Network Policy",
          "All inbound network traffic is denied unless explicitly permitted.", Severity.HIGH, 1.2,
          "Set explicit default-deny rules on NSGs, security groups, and host firewalls.",
          _check_32b_default_deny),
    Check("ART32B-002", "Art.32(1)(b)", "No Internet-Exposed Management Ports",
          "SSH, RDP, and database ports are not accessible from the internet.", Severity.CRITICAL, 1.5,
          "Place management ports behind a VPN or bastion host. Restrict source IPs on NSG rules. Use Azure Bastion or AWS Session Manager.",
          _check_32b_management_ports),
    Check("ART32B-003", "Art.32(1)(b)", "Network Segmentation",
          "The network is segmented into zones (DMZ, application, data).", Severity.HIGH, 1.2,
          "Separate personal data processing into a dedicated network segment. Implement micro-segmentation where feasible.",
          _check_32b_segmentation),
    Check("ART32B-004", "Art.32(1)(b)", "MFA Coverage",
          "MFA is enabled to protect system confidentiality.", Severity.HIGH, 1.0,
          "See ART5-003 for remediation guidance.",
          _check_32b_mfa),
    Check("ART32B-005", "Art.32(1)(b)", "Privileged Access Management",
          "A PAM solution controls and audits privileged access.", Severity.HIGH, 1.0,
          "Deploy a PAM solution (CyberArk, BeyondTrust, Azure PIM) with session recording and just-in-time access.",
          _check_32b_pam),
    Check("ART32B-006", "Art.32(1)(b)", "Wildcard Admin Access Restricted",
          "Broad administrative roles (Owner, Global Admin, *) are eliminated.", Severity.HIGH, 1.0,
          "Audit and remove subscription-level Owner and Global Admin assignments. Replace with scoped, purpose-specific roles.",
          _check_32b_wildcard_admin),

    # Art.32(1)(c)
    Check("ART32C-001", "Art.32(1)(c)", "Backups Enabled",
          "Backups of personal data are taken regularly.", Severity.HIGH, 1.5,
          "Enable automated backups across all systems that hold personal data.",
          _check_32c_backups_enabled),
    Check("ART32C-002", "Art.32(1)(c)", "Backup Frequency",
          "Backups run frequently enough to meet RTO/RPO requirements.", Severity.MEDIUM, 1.0,
          "For production personal data, implement at minimum daily backups — hourly for high-criticality systems.",
          _check_32c_backup_frequency),
    Check("ART32C-003", "Art.32(1)(c)", "Offsite / Geo-Redundant Backups",
          "Backups are stored in a geographically separate location.", Severity.HIGH, 1.2,
          "Configure geo-redundant backup storage (Azure GRS, AWS cross-region replication) to survive regional incidents.",
          _check_32c_offsite),
    Check("ART32C-004", "Art.32(1)(c)", "Backup Restoration Tested",
          "Backup restoration has been verified to work.", Severity.CRITICAL, 1.5,
          "Run restoration tests at least quarterly. Document RTO achieved and remediate gaps.",
          _check_32c_backup_tested),
    Check("ART32C-005", "Art.32(1)(c)", "Backup Encryption",
          "Backup data is encrypted to protect personal data at rest.", Severity.HIGH, 1.2,
          "Enable encryption on backup storage. Ensure keys are managed separately from the backup data.",
          _check_32c_backup_encrypted),

    # Art.32(1)(d)
    Check("ART32D-001", "Art.32(1)(d)", "Vulnerability Scanning",
          "Systems are regularly scanned for known vulnerabilities.", Severity.HIGH, 1.2,
          "Deploy an agent-based or network vulnerability scanner (Qualys, Tenable, Defender CSPM). Integrate findings into a ticketing workflow.",
          _check_32d_scanning),
    Check("ART32D-002", "Art.32(1)(d)", "Scan Frequency",
          "Vulnerability scans run weekly or more frequently.", Severity.MEDIUM, 0.8,
          "Schedule automated scans at minimum weekly. Enable continuous monitoring where the platform supports it.",
          _check_32d_scan_frequency),
    Check("ART32D-003", "Art.32(1)(d)", "Patch Management Policy",
          "A documented policy governs how patches are applied and tracked.", Severity.HIGH, 1.0,
          "Document a patch management policy covering severity-based SLAs, change windows, and exceptions process.",
          _check_32d_patch_policy),
    Check("ART32D-004", "Art.32(1)(d)", "Critical Patch SLA",
          "Critical and high-severity patches are applied within 14 days.", Severity.HIGH, 1.0,
          "Reduce critical patch SLA to ≤14 days. Automate patching via Azure Update Manager, AWS SSM Patch Manager, or equivalent.",
          _check_32d_critical_patch_sla),
    Check("ART32D-005", "Art.32(1)(d)", "Penetration Testing",
          "Annual penetration testing is conducted by a qualified tester.", Severity.HIGH, 1.2,
          "Commission annual penetration testing by a CREST/CHECK-approved provider. Remediate findings and retain evidence.",
          _check_32d_pentest),

    # Art.33
    Check("ART33-001", "Art.33", "SIEM Integration",
          "Logs feed into a SIEM to enable breach detection.", Severity.CRITICAL, 1.5,
          "Integrate all log sources into a SIEM (Microsoft Sentinel, Splunk). Configure detection rules for data exfiltration and unauthorised access.",
          _check_33_siem),
    Check("ART33-002", "Art.33", "Breach Detection Rules",
          "Automated rules exist to detect personal data breaches.", Severity.CRITICAL, 1.5,
          "Write SIEM detection rules for: mass data export, impossible travel, credential stuffing, privilege escalation, and unusual data access patterns.",
          _check_33_breach_rules),
    Check("ART33-003", "Art.33", "72-Hour Notification Capability",
          "The organisation can notify the ICO within 72 hours of discovering a breach.", Severity.CRITICAL, 1.5,
          "Test your breach notification process against the 72-hour SLA. Document ICO notification contacts and pre-approved communication templates.",
          _check_33_72h_capability),
    Check("ART33-004", "Art.33", "Data Breach Register",
          "All breaches (reported or not) are recorded in a register.", Severity.HIGH, 1.0,
          "Maintain a breach register per Art.33(5). Include date, nature, data categories, approximate number of subjects, consequences, and measures taken.",
          _check_33_breach_register),
    Check("ART33-005", "Art.33", "Incident Response Plan",
          "A documented and tested IR plan covers personal data breaches.", Severity.HIGH, 1.2,
          "Document and regularly test an IR plan that includes breach containment, evidence preservation, ICO notification, and subject communication steps.",
          _check_33_ir_plan),
    Check("ART33-006", "Art.33", "DPO Contact Accessibility",
          "The DPO's contact details are documented and accessible during an incident.", Severity.MEDIUM, 0.8,
          "Publish the DPO contact in the IR plan, privacy notice, and on-call rota. Register DPO details with the ICO.",
          _check_33_dpo_contact),

    # Art.35
    Check("ART35-001", "Art.35", "DPIA Completed",
          "A Data Protection Impact Assessment has been completed where required.", Severity.HIGH, 1.5,
          "Conduct a DPIA before beginning high-risk processing. Use the ICO's DPIA template. Document residual risks and mitigation measures.",
          _check_35_dpia_completed),
    Check("ART35-002", "Art.35", "DPO Sign-Off on DPIA",
          "The DPO has reviewed and signed off the DPIA.", Severity.MEDIUM, 1.0,
          "Involve the DPO from the outset of the DPIA process. Obtain formal written approval before processing begins.",
          _check_35_dpo_signoff),
    Check("ART35-003", "Art.35", "DPIA Review Schedule",
          "The DPIA is scheduled for periodic review.", Severity.LOW, 0.5,
          "Schedule DPIA reviews annually or when there is a material change to the nature, scope, or purpose of processing.",
          _check_35_review_schedule),

    # Art.44
    Check("ART44-001", "Art.44", "International Transfer Inventory",
          "All personal data transfers to third countries are identified and documented.", Severity.HIGH, 1.2,
          "Map all data flows to countries outside the UK. Document the transfer basis for each. Include processors, sub-processors, and cloud regions.",
          _check_44_transfer_inventory),
    Check("ART44-002", "Art.44", "Lawful Transfer Mechanism",
          "Each third-country transfer relies on an adequacy decision, SCCs, or BCRs.", Severity.HIGH, 1.2,
          "For each third-country transfer, document the specific mechanism (ICO adequacy list, SCCs from ICO, or BCRs). Review post-Schrems II for EU transfers.",
          _check_44_adequacy_mechanism),
    Check("ART44-003", "Art.44", "Data Residency Documented",
          "The geographic location of personal data storage is documented.", Severity.MEDIUM, 0.8,
          "Document data residency for all cloud services. Enforce residency via Azure Policy, AWS SCPs, or equivalent.",
          _check_44_data_residency),

    # Art.5(1)(b) — Purpose Limitation
    Check("PLIM-001", _ART_5B, "Processing Activities Declared",
          "All purposes for processing personal data are declared in the system configuration.", Severity.HIGH, 1.2,
          "Document processing activities in system.processing_activities. Each entry should map to a lawful basis under Art.6.",
          _check_plim_purposes_declared),
    Check("PLIM-002", _ART_5B, "Lawful Bases Documented",
          "A lawful basis under Art.6 is identified and documented for each processing activity.", Severity.CRITICAL, 1.5,
          "Document the lawful basis (consent, contract, legal obligation, legitimate interests, etc.) for each processing activity and publish it in the privacy notice.",
          _check_plim_lawful_bases),
    Check("PLIM-003", _ART_5B, "Purpose Limitation Technically Enforced",
          "Technical controls prevent personal data being used beyond its declared purpose.", Severity.MEDIUM, 1.0,
          "Implement access controls, data classification tags, and API-level restrictions to enforce purpose boundaries. Supplement with a clear data use policy.",
          _check_plim_purpose_enforcement),

    # Art.5(1)(e) — Storage Limitation
    Check("SLIM-001", _ART_5E, "Data Retention Policy Documented",
          "A formal data retention policy defines how long each category of personal data is kept.", Severity.HIGH, 1.2,
          "Create a retention schedule per data category. Align with statutory minimums (e.g. 7 years for financial records) and GDPR storage limitation principle.",
          _check_slim_retention_policy),
    Check("SLIM-002", _ART_5E, "Per-Category Retention Periods Defined",
          "Maximum retention periods are defined for each category of personal data.", Severity.HIGH, 1.0,
          "Define specific periods per category: customer records, employee records, marketing preferences, audit logs. Review annually.",
          _check_slim_max_retention_defined),
    Check("SLIM-003", _ART_5E, "Automated Deletion at End of Retention",
          "Personal data is automatically deleted at the end of its retention period.", Severity.HIGH, 1.2,
          "Implement scheduled deletion jobs. Log deletions to an immutable audit trail. Include backups, archives, and replicas.",
          _check_slim_automated_deletion),

    # Art.13 — Transparency (Privacy Notice)
    Check("TRANS-001", _ART_13, "Privacy Notice Published",
          "A privacy notice is published and accessible to data subjects at the point of collection.", Severity.CRITICAL, 1.5,
          "Publish a privacy notice covering: controller identity, DPO contact, purposes, lawful bases, retention periods, subject rights, and supervisory authority details (ICO).",
          _check_trans_notice_published),
    Check("TRANS-002", _ART_13, "Privacy Notice Current",
          "The privacy notice has been reviewed and updated within the last 12 months.", Severity.MEDIUM, 0.8,
          "Review the privacy notice at least annually or when processing activities change. Record the review date in the config.",
          _check_trans_notice_current),
    Check("TRANS-003", _ART_13, "Lawful Bases Communicated to Data Subjects",
          "Lawful bases for each processing activity are documented and communicated via the privacy notice.", Severity.HIGH, 1.2,
          "Art.13(1)(c) requires the lawful basis to be communicated at the time of collection. Ensure the privacy notice lists the basis per processing purpose.",
          _check_trans_lawful_bases_accessible),

    # Art.17 — Right to Erasure
    Check("ERAS-001", _ART_17, "Erasure Request Process Documented",
          "A documented process exists for receiving, verifying, and completing erasure requests.", Severity.HIGH, 1.2,
          "Document the end-to-end erasure process: receipt channel, identity verification, systems to erase from, downstream notification, and confirmation to the data subject.",
          _check_eras_process_documented),
    Check("ERAS-002", _ART_17, "Erasure SLA Within 1 Calendar Month",
          "Erasure requests are completed within 1 calendar month as required by UK GDPR.", Severity.HIGH, 1.2,
          "UK GDPR Art.12(3) requires response within 1 month, extendable by 2 months for complexity. Set your SLA at ≤30 days and monitor compliance.",
          _check_eras_sla),
    Check("ERAS-003", _ART_17, "Deletion Verified With Audit Trail",
          "Completed erasure requests are verified and logged in an immutable audit trail.", Severity.MEDIUM, 1.0,
          "Require a deletion confirmation step (query/log showing zero results) before closing each request. Store the audit record for at least 3 years.",
          _check_eras_verified_deletion),
    Check("ERAS-004", _ART_17, "Technical Capability to Delete Personal Data",
          "The system has the technical capability to delete personal data on request, including from backups.", Severity.HIGH, 1.2,
          "For append-only stores or immutable backups, implement pseudonymisation or cryptographic erasure (key destruction). Document which data stores support full deletion vs. pseudonymisation.",
          _check_eras_technical_capability),
]

CHECKS_BY_ARTICLE: dict[str, list[Check]] = {}
for _c in ALL_CHECKS:
    CHECKS_BY_ARTICLE.setdefault(_c.article_id, []).append(_c)
