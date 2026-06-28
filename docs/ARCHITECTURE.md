# Architecture

## Overview

GDPR Security Mapper follows a linear pipeline: **parse → assess → report**. Each stage is independent, making it easy to add new input formats, compliance checks, or output renderers without touching the others.

```
Input Config
(YAML / NSG JSON / SG JSON)
        │
        ▼
   ┌─────────┐
   │ Parser  │  Translates native formats into a unified SecurityConfig
   └────┬────┘
        │  SecurityConfig (Pydantic model, all fields Optional)
        ▼
   ┌─────────────────┐
   │ Compliance      │  Runs one Check function per control (62 total)
   │ Engine          │  Each check → (status, evidence, finding)
   └────────┬────────┘
            │  ComplianceReport
            ├──────────────────────┐
            ▼                      ▼
   ┌──────────────┐      ┌────────────────┐
   │ Console      │      │ JSON reporter  │
   │ (Rich)       │      │                │
   └──────────────┘      └────────────────┘
            │
            ▼
   ┌──────────────┐
   │ PDF reporter │
   │ (ReportLab)  │
   └──────────────┘
            │
            ▼
   ┌──────────────┐
   │ Streamlit    │  Optional interactive web layer
   │ Dashboard    │
   └──────────────┘
```

---

## Data models

### `SecurityConfig` ([gdpr_mapper/models/config_input.py](../gdpr_mapper/models/config_input.py))

The unified input model. Every leaf field is `Optional` — this is deliberate. When a user doesn't declare a value, checks return `PARTIAL (not assessed)` rather than a false `GAP`, preventing configs from appearing more compliant or more non-compliant than they are.

Top-level sections map to natural security control domains:

```
SecurityConfig
├── SystemInfo           name, environment, data_classification
├── FirewallConfig       default_ingress, rules[], network_segmentation
├── EncryptionConfig     at_rest, in_transit, key_rotation
├── AccessControlConfig  mfa, privileged_access, rbac, admin_access
├── LoggingConfig        audit_logging, retention, siem_integration, alerting
├── IncidentResponseConfig
├── DataProtectionConfig
├── BackupConfig
├── VulnerabilityManagementConfig
├── DPIAConfig
├── InternationalTransfersConfig
└── ThirdPartyProcessorsConfig
```

### `ComplianceReport` ([gdpr_mapper/models/compliance.py](../gdpr_mapper/models/compliance.py))

Output model. Computed properties (`overall_score`, `overall_status`, `all_gaps`) are derived at access time so they always reflect the underlying check results.

```
ComplianceReport
├── system_name, generated_at, config_source
├── overall_score      (float 0.0–1.0, avg of article scores)
├── overall_status     (SATISFIED / PARTIAL / GAP)
└── articles[]
    └── ArticleResult
        ├── article_id, article_title, article_summary
        ├── score       (weighted avg of check scores)
        ├── status      (≥0.80 → SATISFIED, ≥0.45 → PARTIAL, else GAP)
        └── checks[]
            └── CheckResult
                ├── check_id, article_id, control_name
                ├── status   (SATISFIED / PARTIAL / GAP / N/A)
                ├── evidence (what was found in the config)
                ├── finding  (why it's not satisfied, if applicable)
                └── remediation
```

---

## Compliance engine

### Check definition ([gdpr_mapper/engine/checks.py](../gdpr_mapper/engine/checks.py))

Each check is a `Check` dataclass with an `evaluate` callable:

```python
@dataclass
class Check:
    id: str
    article_id: str
    name: str
    description: str
    severity: Severity      # CRITICAL / HIGH / MEDIUM / LOW
    weight: float           # relative weight within the article
    remediation: str
    evaluate: Callable[[SecurityConfig], tuple[ComplianceStatus, str, str]]
    #                                           status  evidence  finding
```

The `evaluate` function receives the full `SecurityConfig` and returns a three-tuple. This design means:
- Checks are pure functions (no side effects, easily testable)
- Checks can inspect any part of the config — some checks reuse logic from other articles (e.g. the TLS check appears in both Art.5(1)(f) and Art.32(1)(a))
- Adding a new check requires only defining the function and the `Check` object — no mapper changes needed

### Mapper ([gdpr_mapper/engine/mapper.py](../gdpr_mapper/engine/mapper.py))

`run_assessment()` is the single public function. It iterates `ARTICLE_ORDER`, runs every check for that article, and assembles an `ArticleResult`. The mapper owns:
- Article ordering (controls display order in all outputs)
- Article metadata (title and summary text)
- No scoring logic — scoring is on the model classes

### Scoring

Weighted scoring per article:

```
article_score = Σ(check.score × check.weight) / Σ(check.weight)
```

Where `check.score` is `1.0` for SATISFIED/N/A, `0.5` for PARTIAL, `0.0` for GAP.

CRITICAL checks have `weight=1.5`, HIGH checks `1.2–1.0`, MEDIUM `0.8–1.0`, LOW `0.5–0.8`. This means a single CRITICAL gap has a disproportionate negative effect on the article score, as intended.

---

## Parsers

All three parsers produce a `SecurityConfig` from different native formats:

| Parser | Input | Fields populated |
|--------|-------|-----------------|
| `unified.py` | Native YAML | All sections |
| `azure_nsg.py` | `az network nsg show -o json` | `firewall` only |
| `aws_sg.py` | `aws ec2 describe-security-groups` | `firewall` only |

When only `firewall` is populated, checks for other sections return `PARTIAL (not assessed)` — the score is dragged down compared to a full YAML config, but no false gaps are generated. This is the correct behaviour when only partial config data is available.

---

## Reporters

| Reporter | Output | Entry point |
|----------|--------|-------------|
| `ConsoleReporter` | Rich terminal tables | `reporter.render(report)` |
| `JsonReporter` | JSON file or stdout | `reporter.render(report)` |
| `PdfReporter` | ReportLab PDF | `reporter.render(report)` |

The PDF reporter uses ReportLab's Platypus flowable system with a custom page template (`_header_footer`) that renders on every page. The document structure is:

1. Cover page — score badge, metadata table
2. Executive summary — article scorecard, critical gaps
3. Detailed findings — one section per article, check-level table
4. Remediation roadmap — priority-sorted action table (max 30 rows)

---

## Streamlit dashboard ([gdpr_mapper/app.py](../gdpr_mapper/app.py))

The app is stateless — `st.session_state.report` holds the last assessment result. The sidebar handles file upload and triggers `_run_from_path()`, which calls the same `run_assessment()` used by the CLI.

Tab structure:
- `tab_overview` — Plotly gauge + bar chart + Pandas summary table
- `tab_article_detail` — per-article selector + check table
- `tab_gap_analysis` — severity pie chart + priority remediation table
- `tab_evidence` — searchable, filterable evidence log (all checks)
- `tab_export` — `st.download_button` for JSON and PDF

---

## Extension points

**Add a new GDPR article:** Add `Check` objects to `checks.py` with the new `article_id`, add the article to `ARTICLE_META` in `mapper.py`, and add it to `ARTICLE_ORDER`.

**Add a new input format:** Create `parsers/my_format.py` implementing `parse_my_format(path) -> SecurityConfig`. Register it in `parsers/__init__.py` and expose it as a `--format` option in `cli.py`.

**Add a new output format:** Create `reporters/my_reporter.py` with a `render(report: ComplianceReport) -> None` method. Add the option to `cli.py`.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `pydantic>=2.5` | Input schema validation with Optional fields |
| `click>=8.1` | CLI framework |
| `pyyaml>=6.0` | YAML config parsing |
| `rich>=13.0` | Console formatting |
| `streamlit>=1.30` | Web dashboard |
| `plotly>=5.18` | Interactive charts in dashboard |
| `pandas>=2.1` | Dataframes for Streamlit tables |
| `reportlab>=4.0` | PDF generation |
