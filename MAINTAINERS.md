# Maintainers

## Current maintainer

| Name | GitHub | Role |
|------|--------|------|
| Abosede-o-Makinde | [@Abosede-o-Makinde](https://github.com/Abosede-o-Makinde) | Project owner — architecture, GDPR mapping logic, reviews |

## What maintainers do

- Review pull requests and leave actionable feedback
- Triage issues and label them sensibly
- Keep `CHANGELOG.md` and version numbers in sync when cutting releases
- Handle security reports privately (see `SECURITY.md`)

## Co-maintainers

If you've merged a few meaningful PRs, understand the UK GDPR mapping in this tool, and can review within a reasonable timeframe, get in touch via the email in `SECURITY.md`.

## Cutting a release

1. Move `[Unreleased]` entries in `CHANGELOG.md` under a new version heading
2. Bump the version in `pyproject.toml`
3. Tag: `git tag -a v1.x.x -m "Release v1.x.x"`
4. Push the tag and draft a GitHub Release from the changelog entry
