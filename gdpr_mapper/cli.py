"""
gdpr-mapper CLI

Commands:
  scan      Scan a security config file and output a compliance report
  sample    Write a blank annotated config template to file
  articles  List all GDPR articles and checks covered by this tool
  serve     Launch the Streamlit web dashboard
"""

from __future__ import annotations
import subprocess
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_config(config_file: str, fmt: str):
    from .parsers import parse_unified, parse_azure_nsg, parse_aws_sg

    parsers = {
        "unified": parse_unified,
        "azure-nsg": parse_azure_nsg,
        "aws-sg": parse_aws_sg,
    }
    parser = parsers.get(fmt)
    if parser is None:
        raise click.BadParameter(f"Unknown format '{fmt}'. Choose: unified, azure-nsg, aws-sg")
    return parser(config_file)


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option("1.0.0", prog_name="gdpr-mapper")
def cli():
    """
    GDPR Security Mapper — maps security configurations to UK GDPR compliance articles.

    Analyse firewall rules, encryption settings, access controls and logging
    configuration against UK GDPR articles (see `gdpr-mapper articles` for coverage).
    """


# ---------------------------------------------------------------------------
# gdpr-mapper scan
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("config_file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["unified", "azure-nsg", "aws-sg"]),
    default="unified",
    show_default=True,
    help="Input config format.",
)
@click.option(
    "--report", "-r",
    type=click.Choice(["console", "json", "pdf", "all"]),
    default="console",
    show_default=True,
    help="Output report format.",
)
@click.option(
    "--output", "-o",
    type=click.Path(dir_okay=False),
    default=None,
    help="Output file path (required for json/pdf).",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Show detailed per-article findings in console output.",
)
def scan(config_file: str, fmt: str, report: str, output: str | None, verbose: bool):
    """Scan CONFIG_FILE and produce a GDPR compliance report.

    \b
    Examples:
      gdpr-mapper scan config.yaml
      gdpr-mapper scan config.yaml --report pdf --output report.pdf
      gdpr-mapper scan nsg.json --format azure-nsg --report console --verbose
      gdpr-mapper scan sg.json --format aws-sg --report all --output result
    """
    from .engine import run_assessment
    from .reporters import ConsoleReporter, JsonReporter, PdfReporter

    with console.status(f"[bold cyan]Loading {fmt} config from {config_file}...[/bold cyan]"):
        try:
            config = _load_config(config_file, fmt)
        except Exception as exc:
            console.print(f"[bold red]Error loading config:[/bold red] {exc}")
            sys.exit(1)

    with console.status("[bold cyan]Running compliance checks...[/bold cyan]"):
        assessment = run_assessment(config, config_source=config_file)

    if report in ("console", "all"):
        ConsoleReporter(verbose=verbose).render(assessment)

    if report in ("json", "all"):
        out_path = _resolve_output(output, ".json", config_file)
        JsonReporter(output=out_path).render(assessment)
        console.print(f"[green]JSON report written to:[/green] {out_path}")

    if report in ("pdf", "all"):
        out_path = _resolve_output(output, ".pdf", config_file)
        try:
            PdfReporter(output=out_path).render(assessment)
            console.print(f"[green]PDF report written to:[/green] {out_path}")
        except ImportError as exc:
            console.print(f"[yellow]PDF generation requires reportlab:[/yellow] pip install reportlab\n{exc}")


def _resolve_output(output: str | None, ext: str, config_file: str) -> Path:
    if output:
        p = Path(output)
        if p.suffix.lower() not in {".pdf", ".json"} and not p.suffix:
            p = p.with_suffix(ext)
        return p
    stem = Path(config_file).stem
    return Path(f"gdpr_report_{stem}{ext}")


# ---------------------------------------------------------------------------
# gdpr-mapper sample
# ---------------------------------------------------------------------------

SAMPLE_CONFIG = """\
# gdpr-security-mapper — Unified Security Configuration
# Fill in each section for your system. Leave fields as null/omit if not assessed.
# Run:  gdpr-mapper scan this_file.yaml

system:
  name: "My Production System"
  description: "Customer-facing API and data platform"
  environment: production           # production | staging | development
  data_classification: personal     # personal | sensitive | public
  contains_special_category: false  # true if processing health, biometric, etc.
  data_subjects_count: 10000
  processing_activities:
    - "User registration and authentication"
    - "Order processing and fulfilment"

firewall:
  default_ingress: deny             # deny | allow  (deny = privacy-by-design)
  default_egress: allow
  network_segmentation: true
  zones: [dmz, application, database]
  rules:
    - name: "Allow HTTPS inbound"
      protocol: TCP
      port: "443"
      source: "0.0.0.0/0"
      action: allow
      direction: inbound
    - name: "Allow SSH from management range"
      protocol: TCP
      port: "22"
      source: "10.0.1.0/24"
      action: allow
      direction: inbound

encryption:
  at_rest:
    enabled: true
    algorithm: "AES-256"
    key_management: hsm             # manual | managed | hsm
    covers: [database, storage, backups]
  in_transit:
    tls_version: "1.3"
    tls_12_minimum: true
    hsts: true
    certificate_valid: true
    internal_tls: true
  key_rotation:
    enabled: true
    period_days: 90

access_control:
  mfa:
    enabled: true
    applies_to: all                 # all | privileged | none
  privileged_access:
    pam_solution: true
    just_in_time: true
    break_glass_documented: true
  rbac:
    enabled: true
    principle_least_privilege: true
    regular_review: true
    review_frequency_days: 90
  service_accounts:
    inventory_maintained: true
    no_interactive_login: true
    secrets_managed: true
  admin_access:
    wildcard_admin_restricted: true
    default_admin_disabled: true

logging:
  audit_logging:
    enabled: true
    covers:
      - authentication
      - authorization
      - data_access
      - admin_actions
      - configuration_changes
  retention:
    period_days: 365
    immutable: true
  centralized: true
  siem_integration: true
  alerting:
    enabled: true
    breach_detection_rules: true
    anomaly_detection: true

incident_response:
  plan_documented: true
  last_tested: "2026-03-01"
  breach_notification_72h: true
  data_breach_register: true
  dpo_contact_documented: true

data_protection:
  pseudonymisation: true
  anonymisation: false
  data_minimisation_enforced: true
  retention_policy_documented: true
  deletion_capability: true

backups:
  enabled: true
  frequency: daily                  # hourly | daily | weekly | monthly
  offsite: true
  tested: true
  test_frequency: "quarterly"
  encrypted: true

vulnerability_management:
  scanning:
    enabled: true
    frequency: weekly               # daily | weekly | monthly | quarterly | annual
    last_scan: "2026-06-10"
  patching:
    policy_documented: true
    critical_patch_sla_days: 14
  penetration_testing:
    conducted: true
    frequency: annual
    last_test: "2026-01-15"

dpia:
  required: true
  completed: true
  completion_date: "2026-01-20"
  dpo_sign_off: true
  review_schedule: annual

international_transfers:
  transfers_to_third_countries: false
  transfer_mechanisms: []
  data_residency:
    region: "UK"
    documented: true

third_party_processors:
  inventory_maintained: true
  dpas_signed: true
  regular_review: true
"""


@cli.command()
@click.option(
    "--output", "-o",
    type=click.Path(dir_okay=False),
    default="security_config.yaml",
    show_default=True,
    help="Path to write the sample config template.",
)
def sample(output: str):
    """Write an annotated configuration template to file.

    Edit the generated file to reflect your system's actual controls,
    then run: gdpr-mapper scan <file>
    """
    path = Path(output)
    path.write_text(SAMPLE_CONFIG, encoding="utf-8")
    console.print(f"[green]Sample config written to:[/green] {path}")
    console.print(f"[dim]Edit the file, then run: gdpr-mapper scan {path}[/dim]")


# ---------------------------------------------------------------------------
# gdpr-mapper articles
# ---------------------------------------------------------------------------

@cli.command()
def articles():
    """List all GDPR articles and checks covered by this tool."""
    from .engine.checks import CHECKS_BY_ARTICLE, ALL_CHECKS
    from .engine.mapper import ARTICLE_META

    table = Table(
        title=f"UK GDPR Coverage — {len(ALL_CHECKS)} checks across {len(CHECKS_BY_ARTICLE)} articles",
        box=box.ROUNDED,
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("Article", style="bold", width=16)
    table.add_column("Title", width=36)
    table.add_column("Checks", justify="center", width=8)
    table.add_column("Check IDs", width=60)

    for article_id, (title, _) in ARTICLE_META.items():
        checks = CHECKS_BY_ARTICLE.get(article_id, [])
        ids = ", ".join(c.id for c in checks)
        table.add_row(article_id, title, str(len(checks)), ids)

    console.print(table)


# ---------------------------------------------------------------------------
# gdpr-mapper serve
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--port", "-p", default=8501, show_default=True, help="Port for Streamlit.")
@click.option("--host", default="localhost", show_default=True, help="Host to bind Streamlit.")
def serve(port: int, host: str):
    """Launch the Streamlit web dashboard.

    Upload a config file in the browser UI to run an interactive compliance assessment.
    """
    app_path = Path(__file__).parent / "app.py"
    if not app_path.exists():
        console.print("[red]app.py not found.[/red]")
        sys.exit(1)

    console.print(f"[bold cyan]Launching dashboard at http://{host}:{port}[/bold cyan]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]")
    subprocess.run(
        [
            sys.executable, "-m", "streamlit", "run", str(app_path),
            "--server.port", str(port),
            "--server.address", host,
            "--browser.gatherUsageStats", "false",
        ],
        check=False,
    )


if __name__ == "__main__":
    cli()
