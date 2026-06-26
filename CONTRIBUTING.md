# Contributing to gdpr-security-mapper

Thanks for looking at this project. It maps technical security configs to UK GDPR articles — contributions that improve the checks, parsers, docs, or tests are welcome.

## How you can help

- **New checks** — additional controls within an article we already cover
- **New articles** — extend beyond the current 14
- **New parsers** — GCP, Terraform, etc.
- **Bug fixes** — wrong verdicts, crashes, misleading output
- **Docs** — clearer GDPR references, better examples
- **Tests** — edge cases we haven't thought of

For larger changes (new article, new parser), open an issue first so we don't duplicate work.

---

## Development setup

**Requires Python 3.11+**

```bash
git clone https://github.com/Abosede-o-Makinde/gdpr-security-mapper.git
cd gdpr-security-mapper
pip install -e ".[dev]"
```

On Windows (PowerShell), same commands — use `python` instead of `python3` if needed.

Run tests:

```bash
pytest
```

Lint and format:

```bash
ruff check gdpr_mapper/ tests/
ruff format gdpr_mapper/ tests/
```

Quick smoke test:

```bash
gdpr-mapper scan data/sample_configs/sample_compliant.yaml
gdpr-mapper serve
```

---

## Project layout

```
gdpr_mapper/
  models/       # SecurityConfig input + ComplianceReport output
  engine/       # checks.py (62 checks) + mapper.py (orchestrator)
  parsers/      # YAML, Azure NSG, AWS SG
  reporters/    # console, JSON, PDF
  cli.py        # gdpr-mapper commands
  app.py        # Streamlit dashboard
```

Flow: `SecurityConfig` → `run_assessment()` → `ComplianceReport` → reporter

---

## Adding a new check

Checks live in `gdpr_mapper/engine/checks.py`. Each one is a pure function:

`(SecurityConfig) → (ComplianceStatus, evidence, finding)`

### 1. Write the function

```python
def _check_art5b_example(cfg: SecurityConfig):
    value = cfg.some_section.some_field
    if value is None:
        return ComplianceStatus.PARTIAL, _NOT_ASSESSED, "Describe what to configure."
    if value:
        return ComplianceStatus.SATISFIED, "Evidence string for auditors", ""
    return ComplianceStatus.GAP, "What was found", "Specific remediation step."
```

Rules:

- Always return a 3-tuple — never raise inside a check
- Use `_NOT_ASSESSED` when the config field wasn't provided
- Leave `finding` empty on `SATISFIED`

### 2. Register it

Add a `Check` object to `ALL_CHECKS`:

```python
Check(
    "NEWID-001",
    "Art.5(1)(b)",
    "Short control name",
    "One-line description.",
    Severity.HIGH,
    1.0,
    "Remediation guidance.",
    _check_art5b_example,
),
```

### 3. Update tests

In `tests/test_engine.py`, bump the check count:

```python
assert len(ALL_CHECKS) == <new_total>
```

### 4. Update sample configs

If your check reads new fields, add them to:

- `data/sample_configs/sample_compliant.yaml` — satisfied value
- `data/sample_configs/sample_partial.yaml` — partial
- `data/sample_configs/sample_gaps.yaml` — gap

---

## Adding a new article

Touch four places:

1. `gdpr_mapper/models/config_input.py` — new fields on `SecurityConfig`
2. `gdpr_mapper/engine/checks.py` — check functions + `Check` registrations
3. `gdpr_mapper/engine/mapper.py` — `ARTICLE_META` and `ARTICLE_ORDER`
4. `tests/test_engine.py` — article and check counts

Optionally update `docs/GDPR_MAPPING_REFERENCE.md`.

---

## Adding a new parser

Create `gdpr_mapper/parsers/my_provider.py` — read native config, return `SecurityConfig`.

Export from `gdpr_mapper/parsers/__init__.py` and wire a `--format` option in `cli.py`.

Add tests in `tests/test_parsers.py`: happy path, malformed input, minimal/empty input.

---

## Code style

- `ruff format` and `ruff check` (line length 100)
- Type hints on public functions
- Comments only when the *why* isn't obvious

Run `pytest` and `ruff check` before opening a PR.

---

## Branches and commits

| Type | Example branch |
|------|----------------|
| New check | `feat/check-art17-eras005` |
| Bug fix | `fix/art33-false-positive` |
| Parser | `feat/parser-gcp-vpc` |
| Docs | `docs/readme-clarity` |

Commit messages — short subject, optional body:

```
feat(checks): add erasure SLA check for immutable stores
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`

---

## Pull requests

1. Fork and branch from `main`
2. Make changes + tests; confirm `pytest` passes
3. Open a PR with a clear description of what changed and why
4. I'll review when I can — smaller PRs get merged faster

See also `CODE_OF_CONDUCT.md` and `SECURITY.md`.
