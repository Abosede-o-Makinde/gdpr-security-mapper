# GDPR → Security Control Mapping Reference

This document maps each UK GDPR article assessed by this tool to:
- The specific technical controls evaluated
- The CIS Controls v8 reference
- The ISO 27001:2022 Annex A reference
- The MITRE ATT&CK techniques addressed

---

## Art.5(1)(f) — Integrity and Confidentiality

> "processed in a manner that ensures appropriate security of the personal data, including protection against unauthorised or unlawful processing and against accidental loss, destruction or damage, using appropriate technical or organisational measures"

### Controls assessed

| Check ID | Control | Config Field |
|----------|---------|-------------|
| ART5-001 | At-rest encryption | `encryption.at_rest.enabled` |
| ART5-002 | TLS 1.2+ enforcement | `encryption.in_transit.tls_12_minimum` |
| ART5-003 | Multi-factor authentication | `access_control.mfa.enabled` |
| ART5-004 | Audit logging | `logging.audit_logging.enabled` |
| ART5-005 | Role-based access control | `access_control.rbac.enabled` |

### Cross-references

| Framework | Reference |
|-----------|-----------|
| CIS Controls v8 | CIS 3 (Data Protection), CIS 6 (Access Control Management), CIS 8 (Audit Log Management) |
| ISO 27001:2022 | A.5.33 (Protection of records), A.8.3 (Information access restriction), A.8.24 (Use of cryptography) |
| NCSC Cyber Essentials | Access control, Malware protection, Patch management |

### MITRE ATT&CK techniques mitigated

| Technique | ID | How control addresses it |
|-----------|----|--------------------------|
| Brute Force | T1110 | MFA (ART5-003) prevents credential reuse |
| Credential Dumping | T1003 | Encryption at rest (ART5-001) protects credential stores |
| Network Sniffing | T1040 | TLS (ART5-002) prevents in-transit interception |
| Account Manipulation | T1098 | RBAC (ART5-005) limits privilege escalation |
| Indicator Removal | T1070 | Audit logging (ART5-004) provides tamper evidence |

---

## Art.25 — Data Protection by Design and Default

> "the controller shall... implement appropriate technical and organisational measures... designed to implement data-protection principles... in an effective manner"

### Controls assessed

| Check ID | Control | Config Field |
|----------|---------|-------------|
| ART25-001 | Default deny ingress firewall | `firewall.default_ingress` |
| ART25-002 | Principle of least privilege | `access_control.rbac.principle_least_privilege` |
| ART25-003 | Data minimisation enforced | `data_protection.data_minimisation_enforced` |
| ART25-004 | Pseudonymisation | `data_protection.pseudonymisation` |
| ART25-005 | Universal MFA coverage | `access_control.mfa.applies_to == "all"` |

### Design principles mapped

| GDPR Principle (Art.5) | Control | Mechanism |
|----------------------|---------|-----------|
| Purpose limitation | Data minimisation (ART25-003) | Collect only what is declared necessary |
| Data minimisation | Data minimisation (ART25-003) | Schema-level enforcement |
| Integrity & confidentiality | Default deny (ART25-001) | Network-layer protection |
| Accountability | Pseudonymisation (ART25-004) | Reduces breach impact scope |

---

## Art.30 — Records of Processing Activities

> "Each controller... shall maintain a record of processing activities under its responsibility"

### Controls assessed

| Check ID | Control | What it evidences |
|----------|---------|------------------|
| ART30-001 | Authentication event logging | Who accessed systems and when |
| ART30-002 | Data access event logging | What personal data was accessed |
| ART30-003 | Log retention ≥ 180 days | Historical record for investigations |
| ART30-004 | Centralised logging | Queryable audit trail |
| ART30-005 | Third-party processor inventory | Art.30(2) processor record |

### ICO guidance alignment

The ICO's Records of Processing Activities guidance (updated 2023) requires controllers to document:
- Purposes of processing → `system.processing_activities`
- Categories of data subjects → implied by `data_classification`
- Categories of personal data → captured in processor inventory
- Recipients and transfers → `international_transfers`
- Retention periods → `data_protection.retention_policy_documented`
- Security measures → all technical controls in this tool

---

## Art.32(1)(a) — Pseudonymisation and Encryption

### Controls assessed

| Check ID | Control | Threshold |
|----------|---------|-----------|
| ART32A-001 | At-rest encryption enabled | Must be true |
| ART32A-002 | Strong algorithm (AES-256 equiv) | AES-128 minimum, AES-256 recommended |
| ART32A-003 | TLS 1.2+ for data in transit | TLS 1.2 minimum |
| ART32A-004 | TLS 1.3 preferred | Best practice |
| ART32A-005 | Key rotation | ≤90 days for sensitive data |
| ART32A-006 | Pseudonymisation of PII | PARTIAL if absent (recommended) |

### Algorithm guidance

| Algorithm | Assessment | Notes |
|-----------|-----------|-------|
| AES-256 | SATISFIED | NCSC recommended |
| AES-128 | SATISFIED | Acceptable minimum |
| 3DES | GAP | Deprecated — NIST SP 800-131A |
| DES | GAP | Critically weak |
| RC4 | GAP | Broken |
| RSA-2048+ | SATISFIED | For key exchange |
| RSA-1024 | GAP | Insufficient key length |

### TLS version guidance

| Version | Assessment | ICO / NCSC position |
|---------|-----------|---------------------|
| TLS 1.3 | SATISFIED | NCSC recommended |
| TLS 1.2 | SATISFIED | Acceptable with strong cipher suites |
| TLS 1.1 | GAP | Deprecated RFC 8996 (2021) |
| TLS 1.0 | GAP | Deprecated RFC 8996 (2021) |
| SSL 3.0 / SSL 2.0 | GAP | Critically vulnerable (POODLE, DROWN) |

---

## Art.32(1)(b) — Confidentiality, Integrity, Availability, Resilience

### Controls assessed

| Check ID | Control | Rationale |
|----------|---------|-----------|
| ART32B-001 | Default deny network policy | Eliminates unintended exposure |
| ART32B-002 | No internet-exposed management ports | SSH/RDP/DB on internet = critical risk |
| ART32B-003 | Network segmentation | Limits lateral movement |
| ART32B-004 | MFA coverage | Prevents credential-based access |
| ART32B-005 | PAM solution | Controls standing privileged access |
| ART32B-006 | No wildcard admin access | Scoped permissions limit blast radius |

### High-risk port classification

Ports that trigger ART32B-002 when open to `0.0.0.0/0`:

| Port | Service | Risk |
|------|---------|------|
| 22 | SSH | Remote shell |
| 23 | Telnet | Unencrypted remote shell |
| 3389 | RDP | Remote desktop |
| 5985/5986 | WinRM | Remote PowerShell |
| 3306 | MySQL | Database |
| 5432 | PostgreSQL | Database |
| 1433 | MSSQL | Database |
| 27017 | MongoDB | Database |
| 6379 | Redis | Cache / potential data store |
| 9200 | Elasticsearch | Search index (often contains PII) |
| 2375/2376 | Docker daemon | Container control plane |

---

## Art.32(1)(c) — Restore Availability After Incident

### Controls assessed

| Check ID | Control | Recovery objective |
|----------|---------|-------------------|
| ART32C-001 | Backups enabled | Existence of recovery path |
| ART32C-002 | Daily or more frequent backups | RPO ≤ 24 hours |
| ART32C-003 | Offsite / geo-redundant backups | Resilience against site failure |
| ART32C-004 | Backup restoration tested | Verified RTO |
| ART32C-005 | Backup encryption | Personal data protected at rest in backups |

### Backup frequency scoring

| Frequency | Score | Notes |
|-----------|-------|-------|
| Hourly | SATISFIED | Minimum RPO for critical systems |
| Daily | SATISFIED | Standard for production personal data |
| Weekly | PARTIAL | Acceptable only for low-sensitivity/dev |
| Monthly | GAP | Unacceptable data loss window |

---

## Art.32(1)(d) — Regular Testing, Assessing and Evaluating

### Controls assessed

| Check ID | Control | Frequency threshold |
|----------|---------|---------------------|
| ART32D-001 | Vulnerability scanning enabled | — |
| ART32D-002 | Scan frequency | Weekly or more frequent |
| ART32D-003 | Patch management policy | Documented |
| ART32D-004 | Critical patch SLA | ≤14 days (SATISFIED), ≤30 days (PARTIAL) |
| ART32D-005 | Penetration testing | Annual minimum |

### Patch SLA scoring

| Critical patch SLA | Score |
|--------------------|-------|
| ≤14 days | SATISFIED |
| 15–30 days | PARTIAL |
| >30 days | GAP |

NCSC guidance and Cyber Essentials require critical patches applied within 14 days. The ICO has referenced this threshold in enforcement decisions.

---

## Art.33 — Notification of Breach to Supervisory Authority (ICO)

> "the controller shall... notify the personal data breach to the supervisory authority... not later than 72 hours after having become aware of it"

### Controls assessed

| Check ID | Control | Addresses |
|----------|---------|-----------|
| ART33-001 | SIEM integration | Centralised detection capability |
| ART33-002 | Breach detection rules | Automated identification of breaches |
| ART33-003 | 72-hour notification capability | Art.33(1) time constraint |
| ART33-004 | Data breach register | Art.33(5) documentation requirement |
| ART33-005 | IR plan documented | Coordinated response process |
| ART33-006 | DPO contact accessible | Art.33(3)(b) — DPO contact in notification |

### What constitutes a "breach" under Art.4(12)

A personal data breach is a security incident leading to accidental or unlawful:
- **Destruction** → backup failure (ART32C-001-004)
- **Loss** → ransomware without backups (ART32C-001-004)
- **Alteration** → unauthorised write access (ART32B-001-006)
- **Disclosure** → exfiltration, misconfigured access (ART32A, ART32B)
- **Access** → unauthorised read access (ART5, ART25)

### 72-hour notification — ICO requirements

When notifying the ICO (reportablebreach.ico.org.uk), controllers must provide:
1. Nature of the breach and approximate number of subjects affected
2. Contact details of the DPO
3. Likely consequences of the breach
4. Measures taken or proposed to address it

Controls ART33-003 to ART33-006 directly support meeting these requirements.

---

## Art.35 — Data Protection Impact Assessment

> "Where a type of processing... is likely to result in a high risk to the rights and freedoms of natural persons, the controller shall... carry out an assessment of the impact"

### When a DPIA is required (ICO guidance)

A DPIA is mandatory when processing is **likely to result in high risk**, including:
- Systematic and extensive profiling with significant effects
- Large-scale processing of special category data
- Systematic monitoring of publicly accessible areas
- Processing of data concerning vulnerable subjects at scale

Config field: `dpia.required` — if this is `true` and `dpia.completed` is `false`, ART35-001 returns a GAP.

### Controls assessed

| Check ID | Control | Config Field |
|----------|---------|-------------|
| ART35-001 | DPIA completed (if required) | `dpia.required`, `dpia.completed` |
| ART35-002 | DPO sign-off | `dpia.dpo_sign_off` |
| ART35-003 | DPIA review schedule | `dpia.review_schedule` |

---

## Art.44 — General Principle for International Transfers

> "Any transfer of personal data... to a third country... shall take place only if... the conditions laid down in this Chapter are complied with"

### Transfer mechanisms recognised by the ICO (post-Brexit, UK GDPR)

| Mechanism | ICO status |
|-----------|-----------|
| Adequacy regulations | 14 countries/territories as of 2024 (EU, EEA, etc.) |
| UK Standard Contractual Clauses (UK SCCs / IDTA) | Published by ICO, mandatory from March 2024 |
| Binding Corporate Rules (BCRs) | ICO-approved |
| UK derogations (Art.49) | Explicit consent, vital interests, public interest, etc. |

> **Note:** EU Standard Contractual Clauses (pre-Schrems II versions) are **not** valid for UK transfers post-Brexit. The ICO's International Data Transfer Agreement (IDTA) must be used for new UK contracts.

### Controls assessed

| Check ID | Control | Config Field |
|----------|---------|-------------|
| ART44-001 | Transfer inventory documented | `international_transfers.transfers_to_third_countries` + mechanisms |
| ART44-002 | Valid transfer mechanism in place | `international_transfers.transfer_mechanisms[].type` |
| ART44-003 | Data residency documented | `international_transfers.data_residency.documented` |

### Data residency and cloud providers

Cloud region selection directly controls whether Art.44 is engaged:

| Azure Region | UK GDPR status |
|-------------|----------------|
| UK South / UK West | No transfer — domestic |
| Europe North / Europe West | Adequacy decision applies |
| East US / other non-EEA | Transfer — IDTA or SCCs required |

---

## Framework cross-reference summary

| UK GDPR Article | CIS Controls v8 | ISO 27001:2022 Annex A | NCSC CAF |
|----------------|-----------------|------------------------|----------|
| Art.5(1)(f) | 3, 6, 8, 13 | A.8.3, A.8.24, A.5.33 | B3, D1 |
| Art.25 | 4, 6 | A.8.25, A.8.27 | B1, B3 |
| Art.30 | 8 | A.5.28, A.5.33 | D1 |
| Art.32(1)(a) | 3, 13 | A.8.24, A.8.26 | B3 |
| Art.32(1)(b) | 4, 6, 12 | A.8.20, A.8.3, A.8.6 | B2, B3 |
| Art.32(1)(c) | 11 | A.8.13, A.8.14 | B6 |
| Art.32(1)(d) | 7, 16, 18 | A.8.8, A.5.37 | B5 |
| Art.33 | 17 | A.5.24, A.5.25, A.5.26 | C1, D1 |
| Art.35 | 18 | A.5.8 | A4 |
| Art.44 | 3 | A.5.45 | — |

*CIS Controls: 3=Data Protection, 4=Secure Config, 6=Access Control, 7=Vuln Management, 8=Audit Logs, 11=Data Recovery, 12=Network Infra, 13=Network Monitoring, 16=App Security, 17=Incident Response, 18=Pen Testing*
