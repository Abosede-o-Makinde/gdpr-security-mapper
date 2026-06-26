# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x (latest on `main`) | Yes |
| older | No |

## Scope

This policy covers the **gdpr-security-mapper** application — its Python code, CLI, and Streamlit dashboard.

It does **not** cover compliance verdicts about your own systems. The tool is decision-support only; it is not legal advice and does not replace a qualified DPO or counsel.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security bugs.**

Email **abomaabidemi27@gmail.com** with subject:

```
[SECURITY] gdpr-security-mapper — brief description
```

Include:

- What the issue is and why it matters
- Steps to reproduce (or a minimal PoC)
- Which version you tested
- Whether you think it is exploitable in a default install

I'll acknowledge within a few days and follow up with a fix timeline when possible.

## In scope

- Unsafe handling of uploaded YAML/JSON (deserialisation, injection)
- Path traversal or arbitrary file access via CLI arguments
- Issues in the Streamlit app or PDF reporter that allow code execution or data leakage

## Out of scope

- Intentionally weak settings in `data/sample_configs/` — those files are demos
- Wrong GDPR verdicts on a check — open a normal issue for that
- Transitive dependency CVEs with no practical exploit path through this tool

## Disclosure

Once a fix is ready, I'll release a patch, note it in `CHANGELOG.md` (without full exploit detail), and credit you by name unless you prefer to stay anonymous. Please allow ~14 days after the fix is available before public disclosure.
