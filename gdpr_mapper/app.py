"""
Streamlit dashboard for GDPR Security Mapper.

Tabs: Overview, Article Detail, Gap Analysis, Evidence, Export.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from gdpr_mapper.engine import run_assessment
from gdpr_mapper.engine.checks import ALL_CHECKS
from gdpr_mapper.engine.mapper import ARTICLE_META
from gdpr_mapper.models.compliance import ComplianceReport, ComplianceStatus, Severity
from gdpr_mapper.parsers import parse_aws_sg, parse_azure_nsg, parse_unified
from gdpr_mapper.reporters.pdf_rep import PdfReporter
from gdpr_mapper.ui_theme import app_title_html, icon, inject_theme, status_badge, status_text

_STATIC = Path(__file__).parent / "static"
_NUM_CHECKS = len(ALL_CHECKS)
_NUM_ARTICLES = len(ARTICLE_META)

_STATUS_COLOUR = {
    ComplianceStatus.SATISFIED: "#2E7D32",
    ComplianceStatus.PARTIAL: "#F57F17",
    ComplianceStatus.GAP: "#B71C1C",
    ComplianceStatus.NA: "#78909C",
}

_SEV_COLOUR = {
    Severity.CRITICAL: "#B71C1C",
    Severity.HIGH: "#E64A19",
    Severity.MEDIUM: "#F57F17",
    Severity.LOW: "#1976D2",
    Severity.INFO: "#78909C",
}

st.set_page_config(
    page_title="GDPR Security Mapper",
    page_icon=str(_STATIC / "shield.svg"),
    layout="wide",
    initial_sidebar_state="expanded",
)

inject_theme()

if "report" not in st.session_state:
    st.session_state.report = None


def render_sidebar() -> ComplianceReport | None:
    with st.sidebar:
        st.markdown(app_title_html(), unsafe_allow_html=True)
        st.caption("UK GDPR technical compliance assessment")
        st.divider()

        st.subheader("1. Upload config")
        fmt = st.selectbox(
            "Config format",
            options=["unified", "azure-nsg", "aws-sg"],
            format_func=lambda x: {
                "unified": "Unified YAML (recommended)",
                "azure-nsg": "Azure NSG JSON",
                "aws-sg": "AWS Security Group JSON",
            }[x],
        )

        uploaded = st.file_uploader(
            "Configuration file",
            type=["yaml", "yml", "json"],
            help="YAML or JSON security configuration.",
        )

        st.divider()
        st.subheader("2. Run assessment")
        run_btn = st.button("Run assessment", type="primary", use_container_width=True)

        if st.button("Load sample (compliant)", use_container_width=True):
            sample_path = (
                Path(__file__).parent.parent / "data" / "sample_configs" / "sample_compliant.yaml"
            )
            if sample_path.exists():
                _run_from_path(sample_path, "unified")
            else:
                st.error("Sample file not found. Run: pip install -e .")

        if st.button("Load sample (gaps)", use_container_width=True):
            sample_path = (
                Path(__file__).parent.parent / "data" / "sample_configs" / "sample_gaps.yaml"
            )
            if sample_path.exists():
                _run_from_path(sample_path, "unified")
            else:
                st.error("Sample file not found. Run: pip install -e .")

        st.divider()
        st.caption("Assessed against UK GDPR (retained EU law).\nSupervisory authority: ICO.")

        if run_btn and uploaded:
            suffix = ".json" if fmt in ("azure-nsg", "aws-sg") else ".yaml"
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                tmp.write(uploaded.read())
                tmp_path = Path(tmp.name)
            _run_from_path(tmp_path, fmt)

        elif run_btn and not uploaded:
            st.warning("Upload a configuration file first.")

    return st.session_state.report


def _run_from_path(path: Path, fmt: str):
    parsers = {"unified": parse_unified, "azure-nsg": parse_azure_nsg, "aws-sg": parse_aws_sg}
    try:
        with st.spinner("Running compliance checks..."):
            config = parsers[fmt](path)
            report = run_assessment(config, config_source=str(path))
        st.session_state.report = report
        st.success(f"Assessment complete — {report.total_checks} checks run")
    except Exception as exc:
        st.error(f"Failed to parse config: {exc}")


def tab_overview(report: ComplianceReport):
    col_gauge, col_meta = st.columns([2, 3])

    with col_gauge:
        score_pct = report.overall_score * 100
        status = report.overall_status
        col_hex = _STATUS_COLOUR[status]

        fig = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=score_pct,
                number={"suffix": "%", "font": {"size": 40}},
                title={"text": "Overall compliance score", "font": {"size": 14}},
                gauge={
                    "axis": {"range": [0, 100], "tickwidth": 1},
                    "bar": {"color": col_hex, "thickness": 0.25},
                    "bgcolor": "white",
                    "steps": [
                        {"range": [0, 45], "color": "#FFEBEE"},
                        {"range": [45, 80], "color": "#FFF8E1"},
                        {"range": [80, 100], "color": "#E8F5E9"},
                    ],
                    "threshold": {
                        "line": {"color": col_hex, "width": 3},
                        "thickness": 0.75,
                        "value": score_pct,
                    },
                },
            )
        )
        fig.update_layout(height=280, margin=dict(t=40, b=10, l=20, r=20))
        st.plotly_chart(fig, use_container_width=True)

        st.markdown(
            f"<div style='text-align:center;font-size:1.25rem;'>{status_badge(status)}</div>",
            unsafe_allow_html=True,
        )

    with col_meta:
        total = report.total_checks
        gaps = len(report.all_gaps)
        partials = len(report.all_partials)
        satisfied = total - gaps - partials

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total checks", total)
        m2.metric("Satisfied", satisfied)
        m3.metric("Partial", partials)
        m4.metric(
            "Gaps",
            gaps,
            delta=f"-{gaps}" if gaps else None,
            delta_color="inverse",
        )

        st.markdown("**System details**")
        st.markdown(f"- **Name:** {report.system_name}")
        if report.system_description:
            st.markdown(f"- **Description:** {report.system_description}")
        st.markdown(f"- **Assessed:** {report.generated_at.strftime('%d %b %Y, %H:%M UTC')}")
        st.markdown(f"- **Articles:** {len(report.articles)}")

    st.divider()

    article_ids = [a.article_id for a in report.articles]
    article_scores = [a.score * 100 for a in report.articles]
    bar_colours = [_STATUS_COLOUR[a.status] for a in report.articles]

    fig_bar = go.Figure(
        go.Bar(
            x=article_ids,
            y=article_scores,
            marker_color=bar_colours,
            text=[f"{s:.0f}%" for s in article_scores],
            textposition="outside",
            hovertemplate="<b>%{x}</b><br>Score: %{y:.1f}%<extra></extra>",
        )
    )
    fig_bar.update_layout(
        title="Compliance score by GDPR article",
        xaxis_title="Article",
        yaxis_title="Score (%)",
        yaxis_range=[0, 110],
        height=380,
        plot_bgcolor="white",
        showlegend=False,
        margin=dict(t=50, b=40),
    )
    fig_bar.add_hline(
        y=80, line_dash="dash", line_color="#2E7D32", annotation_text="Satisfied threshold (80%)"
    )
    fig_bar.add_hline(
        y=45, line_dash="dash", line_color="#F57F17", annotation_text="Partial threshold (45%)"
    )
    st.plotly_chart(fig_bar, use_container_width=True)

    st.subheader("Article summary")
    rows = []
    for art in report.articles:
        rows.append(
            {
                "Article": art.article_id,
                "Title": art.article_title,
                "Score": f"{art.score * 100:.0f}%",
                "Status": status_text(art.status),
                "Gaps": art.gap_count,
                "Partial": art.partial_count,
                "Satisfied": art.satisfied_count,
                "Top finding": art.top_finding[:80] + "..."
                if len(art.top_finding) > 80
                else art.top_finding,
            }
        )
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def tab_article_detail(report: ComplianceReport):
    article_options = {f"{a.article_id} — {a.article_title}": a for a in report.articles}
    selected_label = st.selectbox("Select article", list(article_options.keys()))
    art = article_options[selected_label]

    col_score, col_status, col_checks = st.columns([1, 1, 2])
    col_score.metric("Score", f"{art.score * 100:.1f}%")
    col_status.metric("Status", art.status.value)
    col_checks.metric(
        "Checks",
        f"{art.satisfied_count} satisfied · {art.partial_count} partial · {art.gap_count} gaps",
    )

    with st.expander("Article text", expanded=False):
        st.caption(art.article_summary)

    st.divider()

    rows = []
    for chk in art.checks:
        rows.append(
            {
                "Check ID": chk.check_id,
                "Control": chk.control_name,
                "Status": status_text(chk.status),
                "Severity": chk.severity.value,
                "Evidence": chk.evidence,
                "Finding": chk.finding,
                "Remediation": chk.remediation,
            }
        )
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def tab_gap_analysis(report: ComplianceReport):
    all_issues = report.all_gaps + report.all_partials
    if not all_issues:
        st.success("No gaps or partial findings — all controls satisfied.")
        return

    sev_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    sorted_issues = sorted(all_issues, key=lambda c: (sev_order.get(c.severity, 5), c.article_id))

    col_pie, col_stats = st.columns([2, 3])
    with col_pie:
        sev_counts: dict[str, int] = {}
        for issue in all_issues:
            sev_counts[issue.severity.value] = sev_counts.get(issue.severity.value, 0) + 1
        fig_pie = go.Figure(
            go.Pie(
                labels=list(sev_counts.keys()),
                values=list(sev_counts.values()),
                hole=0.45,
                marker_colors=[_SEV_COLOUR.get(Severity(k), "#78909C") for k in sev_counts],
            )
        )
        fig_pie.update_layout(title="Issues by severity", height=280, margin=dict(t=40, b=10))
        st.plotly_chart(fig_pie, use_container_width=True)

    with col_stats:
        st.metric("Total issues", len(all_issues))
        c1, c2 = st.columns(2)
        c1.metric("Gaps (score 0)", len(report.all_gaps))
        c2.metric("Partials (score 0.5)", len(report.all_partials))
        crit = sum(1 for i in all_issues if i.severity == Severity.CRITICAL)
        high = sum(1 for i in all_issues if i.severity == Severity.HIGH)
        st.metric("Critical + high", crit + high)
        st.progress(
            (
                len(report.articles)
                - len([a for a in report.articles if a.status == ComplianceStatus.GAP])
            )
            / len(report.articles),
            text="Articles without full gap status",
        )

    st.divider()
    st.subheader("Priority remediation actions")

    rows = []
    for i, issue in enumerate(sorted_issues, 1):
        rows.append(
            {
                "#": i,
                "Severity": issue.severity.value,
                "Type": "GAP" if issue.status == ComplianceStatus.GAP else "PARTIAL",
                "Check ID": issue.check_id,
                "Article": issue.article_id,
                "Control": issue.control_name,
                "Finding": issue.finding,
                "Recommended action": issue.remediation,
            }
        )
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def tab_evidence(report: ComplianceReport):
    st.subheader("Evidence log")
    st.caption("Evidence collected from the configuration during assessment.")

    rows = []
    for art in report.articles:
        for chk in art.checks:
            rows.append(
                {
                    "Article": chk.article_id,
                    "Check ID": chk.check_id,
                    "Control": chk.control_name,
                    "Status": status_text(chk.status),
                    "Score": f"{chk.score:.1f}",
                    "Severity": chk.severity.value,
                    "Evidence": chk.evidence or "—",
                    "Finding": chk.finding or "—",
                }
            )

    df = pd.DataFrame(rows)

    search = st.text_input("Search", placeholder="Filter by check ID, control, or evidence…")
    col_f1, col_f2 = st.columns(2)
    status_filter = col_f1.multiselect(
        "Filter by status",
        options=[s.value for s in ComplianceStatus],
        default=[s.value for s in ComplianceStatus],
    )
    article_filter = col_f2.multiselect(
        "Filter by article",
        options=sorted(df["Article"].unique()),
        default=sorted(df["Article"].unique()),
    )

    mask = df["Article"].isin(article_filter) & df["Status"].isin(status_filter)
    if search.strip():
        needle = search.strip().casefold()
        text_cols = df.columns.difference(["Score"])
        row_match = df[text_cols].astype(str).apply(
            lambda col: col.str.casefold().str.contains(needle, regex=False)
        )
        mask &= row_match.any(axis=1)

    st.dataframe(df[mask], use_container_width=True, hide_index=True)


def tab_export(report: ComplianceReport):
    st.subheader("Export compliance report")

    col_json, col_pdf = st.columns(2)

    with col_json:
        st.markdown(f"### {icon('data_object')} JSON report", unsafe_allow_html=True)
        st.caption("Machine-readable report with all check results and evidence.")
        json_bytes = json.dumps(report.to_dict(), indent=2, ensure_ascii=False).encode("utf-8")
        st.download_button(
            label="Download JSON",
            data=json_bytes,
            file_name=f"gdpr_report_{report.system_name.replace(' ', '_')}.json",
            mime="application/json",
            use_container_width=True,
        )

    with col_pdf:
        st.markdown(f"### {icon('description')} PDF report", unsafe_allow_html=True)
        st.caption("Assessment report with executive summary, findings, and remediation actions.")
        if st.button("Generate PDF", use_container_width=True):
            with st.spinner("Generating PDF..."):
                with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
                    PdfReporter(output=tmp.name).render(report)
                    pdf_bytes = Path(tmp.name).read_bytes()
            st.download_button(
                label="Download PDF",
                data=pdf_bytes,
                file_name=f"gdpr_report_{report.system_name.replace(' ', '_')}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

    st.divider()
    st.subheader("Report summary")
    summary = {
        "system_name": report.system_name,
        "generated_at": report.generated_at.isoformat(),
        "overall_score": f"{report.overall_score * 100:.1f}%",
        "overall_status": report.overall_status.value,
        "total_checks": report.total_checks,
        "gaps": len(report.all_gaps),
        "partials": len(report.all_partials),
        "articles": {
            a.article_id: f"{a.score * 100:.0f}% [{a.status.value}]" for a in report.articles
        },
    }
    st.json(summary)


def main():
    report = render_sidebar()

    if report is None:
        st.markdown(app_title_html(), unsafe_allow_html=True)
        st.markdown(
            '<p class="landing-lead">Map security configuration to UK GDPR compliance.</p>',
            unsafe_allow_html=True,
        )
        st.markdown(
            f"""
This tool analyses firewall rules, encryption, access controls, and logging
against **{_NUM_CHECKS} checks** across **{_NUM_ARTICLES} UK GDPR articles**.

#### Getting started
1. Upload a security config in the sidebar (or load a sample)
2. Click **Run assessment**
3. Review results in the tabs below

#### Supported input formats
| Format | Use case |
|--------|----------|
| **Unified YAML** | Full assessment across all articles |
| **Azure NSG JSON** | `az network nsg show -o json` — firewall checks only |
| **AWS SG JSON** | `aws ec2 describe-security-groups` — firewall checks only |

Generate a blank annotated template: `gdpr-mapper sample --output config.yaml`
            """
        )
        st.info("Upload a configuration file in the sidebar to begin.")
        return

    tabs = st.tabs(["Overview", "Article detail", "Gap analysis", "Evidence", "Export"])
    with tabs[0]:
        tab_overview(report)
    with tabs[1]:
        tab_article_detail(report)
    with tabs[2]:
        tab_gap_analysis(report)
    with tabs[3]:
        tab_evidence(report)
    with tabs[4]:
        tab_export(report)


if __name__ == "__main__":
    main()
