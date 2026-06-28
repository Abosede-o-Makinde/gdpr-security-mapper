"""Rich terminal reporter — formatted tables and panels."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models.compliance import ComplianceReport, ComplianceStatus, Severity

_STATUS_STYLE = {
    ComplianceStatus.SATISFIED: "bold green",
    ComplianceStatus.PARTIAL: "bold yellow",
    ComplianceStatus.GAP: "bold red",
    ComplianceStatus.NA: "dim",
}

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


class ConsoleReporter:
    def __init__(self, verbose: bool = False) -> None:
        self.console = Console()
        self.verbose = verbose

    def render(self, report: ComplianceReport) -> None:
        self._render_header(report)
        self._render_article_summary(report)
        if self.verbose:
            self._render_detailed_findings(report)
        self._render_top_gaps(report)
        self._render_footer(report)

    def _render_header(self, report: ComplianceReport) -> None:
        score_pct = report.overall_score * 100
        status = report.overall_status
        style = _STATUS_STYLE[status]

        score_text = Text()
        score_text.append("\n  ", style="")
        score_text.append("Overall compliance score: ", style="bold")
        score_text.append(f"{score_pct:.1f}%  ", style=style)
        score_text.append(f"[{status.value}]\n", style=style)

        meta_text = Text()
        meta_text.append("  System:     ", style="dim")
        meta_text.append(f"{report.system_name}\n")
        meta_text.append("  Generated:  ", style="dim")
        meta_text.append(f"{report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}\n")
        meta_text.append("  Source:     ", style="dim")
        meta_text.append(f"{report.config_source}\n")
        meta_text.append("  Checks:     ", style="dim")
        total = report.total_checks
        gaps = len(report.all_gaps)
        partials = len(report.all_partials)
        satisfied = total - gaps - partials
        meta_text.append(f"{satisfied} satisfied  /  {partials} partial  /  {gaps} gaps\n")
        meta_text.append("  Confidence: ", style="dim")
        conf_pct = report.config_confidence * 100
        if conf_pct >= 75:
            conf_style = "green"
        elif conf_pct >= 40:
            conf_style = "yellow"
        else:
            conf_style = "red"
        meta_text.append(f"{conf_pct:.0f}% of checks have evidence", style=conf_style)
        if report.special_category_data:
            meta_text.append("  [Art.9 uplift: threshold raised to 90%]", style="bold yellow")
        meta_text.append("\n")

        self.console.print(
            Panel(
                Text.assemble(score_text, meta_text),
                title="[bold]UK GDPR compliance assessment[/bold]",
                border_style=style.replace("bold ", ""),
                padding=(0, 1),
            )
        )

    def _render_article_summary(self, report: ComplianceReport) -> None:
        table = Table(
            title="Article Compliance Summary",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
            expand=True,
        )
        table.add_column("Article", style="bold", width=16)
        table.add_column("Title", width=36)
        table.add_column("Score", justify="right", width=8)
        table.add_column("Status", justify="center", width=12)
        table.add_column("Gaps", justify="center", width=6)
        table.add_column("Partial", justify="center", width=8)
        table.add_column("Top Finding", width=40, no_wrap=False)

        for art in report.articles:
            status = art.status
            style = _STATUS_STYLE[status]
            finding = art.top_finding
            if len(finding) > 60:
                finding = finding[:57] + "..."
            table.add_row(
                art.article_id,
                art.article_title,
                f"{art.score * 100:.0f}%",
                Text(status.value, style=style),
                str(art.gap_count) if art.gap_count else "-",
                str(art.partial_count) if art.partial_count else "-",
                Text(finding, style="dim" if status == ComplianceStatus.SATISFIED else ""),
            )

        self.console.print(table)

    def _render_detailed_findings(self, report: ComplianceReport) -> None:
        for art in report.articles:
            if art.gap_count == 0 and art.partial_count == 0:
                continue

            table = Table(
                title=f"{art.article_id} — {art.article_title}",
                box=box.SIMPLE_HEAVY,
                header_style="bold",
                expand=True,
            )
            table.add_column("ID", width=12)
            table.add_column("Control", width=28)
            table.add_column("Status", width=12)
            table.add_column("Evidence / Finding", width=50)
            table.add_column("Sev", width=9)

            for chk in art.checks:
                if chk.status == ComplianceStatus.SATISFIED:
                    continue
                status_style = _STATUS_STYLE[chk.status]
                sev_style = _SEVERITY_STYLE.get(chk.severity, "")
                detail = chk.finding or chk.evidence
                table.add_row(
                    chk.check_id,
                    chk.control_name,
                    Text(chk.status.value, style=status_style),
                    detail,
                    Text(chk.severity.value, style=sev_style),
                )

            self.console.print(table)

    def _render_top_gaps(self, report: ComplianceReport) -> None:
        gaps = report.all_gaps[:10]
        if not gaps:
            self.console.print(
                Panel(
                    "[green]No gaps identified — all controls satisfied.[/green]",
                    border_style="green",
                )
            )
            return

        table = Table(
            title=f"Top Priority Gaps ({len(report.all_gaps)} total)",
            box=box.ROUNDED,
            header_style="bold red",
            expand=True,
        )
        table.add_column("#", width=3)
        table.add_column("Check", width=12)
        table.add_column("Severity", width=10)
        table.add_column("Article", width=14)
        table.add_column("Control", width=28)
        table.add_column("Remediation (summary)", width=50)

        for i, gap in enumerate(gaps, 1):
            sev_style = _SEVERITY_STYLE.get(gap.severity, "")
            remediation = gap.remediation
            if len(remediation) > 80:
                remediation = remediation[:77] + "..."
            table.add_row(
                str(i),
                gap.check_id,
                Text(gap.severity.value, style=sev_style),
                gap.article_id,
                gap.control_name,
                remediation,
            )

        self.console.print(table)

    def _render_footer(self, report: ComplianceReport) -> None:
        self.console.print(
            f"\n[dim]Framework: UK GDPR | Supervisory Authority: ICO | "
            f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')} | "
            f"gdpr-security-mapper v1.0.0[/dim]\n"
        )
