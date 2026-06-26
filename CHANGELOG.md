# Changelog

Notable changes to this project are listed here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [1.0.0] — 2026-06-26

First public release.

### Added

- 62 compliance checks across 14 UK GDPR articles (Art.5, 13, 17, 25, 30, 32, 33, 35, 44)
- Pydantic v2 input schema with optional fields — partial configs degrade gracefully
- Weighted scoring with Art.9 risk uplift for special category data
- Config confidence score showing how much of the assessment is based on declared evidence
- CLI: `scan`, `sample`, `articles`, `serve`
- Streamlit dashboard with Overview, Article Detail, Gap Analysis, Evidence, and Export tabs
- Reporters: Rich console, JSON, and ReportLab PDF
- Parsers: unified YAML, Azure NSG JSON, AWS Security Group JSON
- Sample configs for compliant, partial, and gap scenarios
- Architecture guide and GDPR mapping reference (`docs/`)
- Contributor docs: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `MAINTAINERS.md`

[Unreleased]: https://github.com/Abosede-o-Makinde/gdpr-security-mapper/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Abosede-o-Makinde/gdpr-security-mapper/releases/tag/v1.0.0
