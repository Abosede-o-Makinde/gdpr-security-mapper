"""
Streamlit dashboard for GDPR Security Mapper.

Tabs:
  📊 Overview        — gauge, per-article bar chart, summary table
  📋 Article Detail  — per-article check table with evidence
  ⚠️  Gap Analysis   — gaps and partials, priority sorted
  🔍 Evidence        — raw evidence log from all checks
  📥 Export          — download JSON and PDF reports
"""

from __future__ import annotations
import io
import json
import tempfile
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st

from gdpr_mapper.engine import run_assessment
from gdpr_mapper.models.compliance import ComplianceReport, ComplianceStatus, Severity
from gdpr_mapper.parsers import parse_unified, parse_azure_nsg, parse_aws_sg
from gdpr_mapper.reporters.pdf_rep import PdfReporter

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="GDPR Security Mapper",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

_STATUS_COLOUR = {
    ComplianceStatus.SATISFIED: "#2E7D32",
    ComplianceStatus.PARTIAL: "#F57F17",
    ComplianceStatus.GAP: "#B71C1C",
    ComplianceStatus.NA: "#78909C",
}

_STATUS_EMOJI = {
    ComplianceStatus.SATISFIED: "✅",
    ComplianceStatus.PARTIAL: "⚠️",
    ComplianceStatus.GAP: "❌",
    ComplianceStatus.NA: "➖",
}

_SEV_COLOUR = {
    Severity.CRITICAL: "#B71C1C",
    Severity.HIGH: "#E64A19",
    Severity.MEDIUM: "#F57F17",
    Severity.LOW: "#1976D2",
    Severity.INFO: "#78909C",
}

# ---------------------------------------------------------------------------
# Session state init
# ---------------------------------------------------------------------------
if "report" not in st.session_state:
    st.session_state.report = None


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
def render_sidebar() -> ComplianceReport | None:
    with st.sidebar:
        st.title("🛡️ GDPR Security Mapper")
        st.caption("UK GDPR Technical Compliance Assessment")
        st.divider()

        st.subheader("1. Upload Config")
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
            "Drop your config file here",
            type=["yaml", "yml", "json"],
            help="Upload a YAML or JSON security configuration file.",
        )

        st.divider()
        st.subheader("2. Run Assessment")
        run_btn = st.button("▶  Run Assessment", type="primary", use_container_width=True)

        if st.button("📄 Load sample (compliant)", use_container_width=True):
            sample_path = Path(__file__).parent.parent / "data" / "sample_configs" / "sample_compliant.yaml"
            if sample_path.exists():
                _run_from_path(sample_path, "unified")
            else:
                st.error("Sample file not found. Run: make install")

        if st.button("⚠️  Load sample (gaps)", use_container_width=True):
            sample_path = Path(__file__).parent.parent / "data" / "sample_configs" / "sample_gaps.yaml"
            if sample_path.exists():
                _run_from_path(sample_path, "unified")
            else:
                st.error("Sample file not found. Run: make install")

        st.divider()
        st.caption("Assessed against UK GDPR (retained EU law).\nSupervisory Authority: ICO.")

        if run_btn and uploaded:
            suffix = ".json" if fmt in ("azure-nsg", "aws-sg") else ".yaml"
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                tmp.write(uploaded.read())
                tmp_path = Path(tmp.name)
            _run_from_path(tmp_path, fmt)

        elif run_btn and not uploaded:
            st.warning("Please upload a config file first.")

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


# ---------------------------------------------------------------------------
# Tab: Overview
# ---------------------------------------------------------------------------
def tab_overview(report: ComplianceReport):
    col_gauge, col_meta = st.columns([2, 3])

    with col_gauge:
        score_pct = report.overall_score * 100
        status = report.overall_status
        col_hex = _STATUS_COLOUR[status]

        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score_pct,
            number={"suffix": "%", "font": {"size": 40}},
            title={"text": "Overall Compliance Score", "font": {"size": 14}},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1},
                "bar": {"color": col_hex, "thickness": 0.25},
                "bgcolor": "white",
                "steps": [
                    {"range": [0, 45], "color": "#FFEBEE"},
                    {"range": [45, 80], "color": "#FFF8E1"},
                    {"range": [80, 100], "color": "#E8F5E9"},
                ],
                "threshold": {"line": {"color": col_hex, "width": 3}, "thickness": 0.75, "value": score_pct},
            },
        ))
        fig.update_layout(height=280, margin=dict(t=40, b=10, l=20, r=20))
        st.plotly_chart(fig, use_container_width=True)

        st.markdown(
            f"<div style='text-align:center;font-size:22px;color:{col_hex};font-weight:bold;'>"
            f"{_STATUS_EMOJI[status]} {status.value}</div>",
            unsafe_allow_html=True,
        )

    with col_meta:
        total = report.total_checks
        gaps = len(report.all_gaps)
        partials = len(report.all_partials)
        satisfied = total - gaps - partials

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Checks", total)
        m2.metric("✅ Satisfied", satisfied, delta=None)
        m3.metric("⚠️ Partial", partials)
        m4.metric("❌ Gaps", gaps, delta=f"-{gaps}" if gaps else None,
                  delta_color="inverse")

        st.markdown("**System Details**")
        st.markdown(f"- **Name:** {report.system_name}")
        if report.system_description:
            st.markdown(f"- **Description:** {report.system_description}")
        st.markdown(f"- **Assessed:** {report.generated_at.strftime('%d %b %Y, %H:%M UTC')}")
        st.markdown(f"- **Articles:** {len(report.articles)}")

    st.divider()

    # Per-article bar chart
    article_ids = [a.article_id for a in report.articles]
    article_scores = [a.score * 100 for a in report.articles]
    article_statuses = [a.status.value for a in report.articles]
    bar_colours = [_STATUS_COLOUR[a.status] for a in report.articles]

    fig_bar = go.Figure(go.Bar(
        x=article_ids,
        y=article_scores,
        marker_color=bar_colours,
        text=[f"{s:.0f}%" for s in article_scores],
        textposition="outside",
        hovertemplate="<b>%{x}</b><br>Score: %{y:.1f}%<extra></extra>",
    ))
    fig_bar.update_layout(
        title="Compliance Score by GDPR Article",
        xaxis_title="Article",
        yaxis_title="Score (%)",
        yaxis_range=[0, 110],
        height=380,
        plot_bgcolor="white",
        showlegend=False,
        margin=dict(t=50, b=40),
    )
    fig_bar.add_hline(y=80, line_dash="dash", line_color="#2E7D32", annotation_text="Satisfied threshold (80%)")
    fig_bar.add_hline(y=45, line_dash="dash", line_color="#F57F17", annotation_text="Partial threshold (45%)")
    st.plotly_chart(fig_bar, use_container_width=True)

    # Summary table
    st.subheader("Article Summary")
    rows = []
    for art in report.articles:
        rows.append({
            "Article": art.article_id,
            "Title": art.article_title,
            "Score": f"{art.score * 100:.0f}%",
            "Status": f"{_STATUS_EMOJI[art.status]} {art.status.value}",
            "Gaps": art.gap_count,
            "Partial": art.partial_count,
            "Satisfied": art.satisfied_count,
            "Top Finding": art.top_finding[:80] + "..." if len(art.top_finding) > 80 else art.top_finding,
        })
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True)


# ---------------------------------------------------------------------------
# Tab: Article Detail
# ---------------------------------------------------------------------------
def tab_article_detail(report: ComplianceReport):
    article_options = {f"{a.article_id} — {a.article_title}": a for a in report.articles}
    selected_label = st.selectbox("Select article", list(article_options.keys()))
    art = article_options[selected_label]

    col_score, col_status, col_checks = st.columns([1, 1, 2])
    col_score.metric("Score", f"{art.score * 100:.1f}%")
    col_status.metric("Status", f"{_STATUS_EMOJI[art.status]} {art.status.value}")
    col_checks.metric("Checks", f"{art.satisfied_count} ✅  {art.partial_count} ⚠️  {art.gap_count} ❌")

    with st.expander("Article text", expanded=False):
        st.caption(art.article_summary)

    st.divider()

    rows = []
    for chk in art.checks:
        rows.append({
            "Check ID": chk.check_id,
            "Control": chk.control_name,
            "Status": f"{_STATUS_EMOJI[chk.status]} {chk.status.value}",
            "Severity": chk.severity.value,
            "Evidence": chk.evidence,
            "Finding": chk.finding,
            "Remediation": chk.remediation,
        })
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True)


# ---------------------------------------------------------------------------
# Tab: Gap Analysis
# ---------------------------------------------------------------------------
def tab_gap_analysis(report: ComplianceReport):
    all_issues = report.all_gaps + report.all_partials
    if not all_issues:
        st.success("🎉 No gaps or partial findings — all controls satisfied.")
        return

    sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                 Severity.LOW: 3, Severity.INFO: 4}
    sorted_issues = sorted(all_issues, key=lambda c: (sev_order.get(c.severity, 5), c.article_id))

    # Severity distribution pie
    col_pie, col_stats = st.columns([2, 3])
    with col_pie:
        sev_counts = {}
        for issue in all_issues:
            sev_counts[issue.severity.value] = sev_counts.get(issue.severity.value, 0) + 1
        fig_pie = go.Figure(go.Pie(
            labels=list(sev_counts.keys()),
            values=list(sev_counts.values()),
            hole=0.45,
            marker_colors=[_SEV_COLOUR.get(Severity(k), "#78909C") for k in sev_counts],
        ))
        fig_pie.update_layout(title="Issues by Severity", height=280, margin=dict(t=40, b=10))
        st.plotly_chart(fig_pie, use_container_width=True)

    with col_stats:
        st.metric("Total Issues", len(all_issues))
        c1, c2 = st.columns(2)
        c1.metric("Gaps (score 0)", len(report.all_gaps))
        c2.metric("Partials (score 0.5)", len(report.all_partials))
        crit = sum(1 for i in all_issues if i.severity == Severity.CRITICAL)
        high = sum(1 for i in all_issues if i.severity == Severity.HIGH)
        st.metric("Critical + High", crit + high)
        st.progress((len(report.articles) * 1 - len([a for a in report.articles
                     if a.status == ComplianceStatus.GAP])) / len(report.articles),
                    text="Articles without full gap status")

    st.divider()
    st.subheader("Priority Remediation Actions")

    rows = []
    for i, issue in enumerate(sorted_issues, 1):
        rows.append({
            "#": i,
            "Severity": issue.severity.value,
            "Type": "GAP" if issue.status == ComplianceStatus.GAP else "PARTIAL",
            "Check ID": issue.check_id,
            "Article": issue.article_id,
            "Control": issue.control_name,
            "Finding": issue.finding,
            "Recommended Action": issue.remediation,
        })

    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True)


# ---------------------------------------------------------------------------
# Tab: Evidence
# ---------------------------------------------------------------------------
def tab_evidence(report: ComplianceReport):
    st.subheader("Evidence Log — All Checks")
    st.caption("Raw evidence collected from the configuration during assessment.")

    rows = []
    for art in report.articles:
        for chk in art.checks:
            rows.append({
                "Article": chk.article_id,
                "Check ID": chk.check_id,
                "Control": chk.control_name,
                "Status": f"{_STATUS_EMOJI[chk.status]} {chk.status.value}",
                "Score": f"{chk.score:.1f}",
                "Severity": chk.severity.value,
                "Evidence": chk.evidence or "—",
                "Finding": chk.finding or "—",
            })

    df = pd.DataFrame(rows)

    # Filter controls
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

    mask = df["Article"].isin(article_filter) & df["Status"].str.contains(
        "|".join(status_filter), regex=True
    )
    st.dataframe(df[mask], use_container_width=True, hide_index=True)


# ---------------------------------------------------------------------------
# Tab: Export
# ---------------------------------------------------------------------------
def tab_export(report: ComplianceReport):
    st.subheader("Export Compliance Report")

    col_json, col_pdf = st.columns(2)

    with col_json:
        st.markdown("### 📄 JSON Report")
        st.caption("Machine-readable full report with all check results and evidence.")
        json_bytes = json.dumps(report.to_dict(), indent=2, ensure_ascii=False).encode("utf-8")
        st.download_button(
            label="⬇ Download JSON",
            data=json_bytes,
            file_name=f"gdpr_report_{report.system_name.replace(' ', '_')}.json",
            mime="application/json",
            use_container_width=True,
        )

    with col_pdf:
        st.markdown("### 📋 PDF Report")
        st.caption("Professional assessment report with executive summary, article findings, and remediation roadmap.")
        if st.button("Generate PDF", use_container_width=True):
            with st.spinner("Generating PDF..."):
                with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
                    PdfReporter(output=tmp.name).render(report)
                    pdf_bytes = Path(tmp.name).read_bytes()
            st.download_button(
                label="⬇ Download PDF",
                data=pdf_bytes,
                file_name=f"gdpr_report_{report.system_name.replace(' ', '_')}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

    st.divider()
    st.subheader("Report Summary (JSON preview)")
    summary = {
        "system_name": report.system_name,
        "generated_at": report.generated_at.isoformat(),
        "overall_score": f"{report.overall_score * 100:.1f}%",
        "overall_status": report.overall_status.value,
        "total_checks": report.total_checks,
        "gaps": len(report.all_gaps),
        "partials": len(report.all_partials),
        "articles": {a.article_id: f"{a.score * 100:.0f}% [{a.status.value}]" for a in report.articles},
    }
    st.json(summary)


# ---------------------------------------------------------------------------
# Main layout
# ---------------------------------------------------------------------------
def main():
    report = render_sidebar()

    if report is None:
        st.title("🛡️ GDPR Security Mapper")
        st.markdown("""
        **Map your security configuration to UK GDPR compliance.**

        This tool analyses firewall rules, encryption settings, access controls, and logging
        configuration against **49 checks** across **10 UK GDPR articles**.

        #### Getting started
        1. Upload a security config file in the sidebar (or load a sample)
        2. Click **▶ Run Assessment**
        3. Explore the results across the tabs below

        #### Supported input formats
        | Format | Use case |
        |--------|----------|
        | **Unified YAML** | Full assessment across all 10 articles |
        | **Azure NSG JSON** | `az network nsg show -o json` — firewall checks only |
        | **AWS SG JSON** | `aws ec2 describe-security-groups` — firewall checks only |

        > 💡 Use `gdpr-mapper sample --output config.yaml` to generate a blank annotated template.
        """)

        st.info("⬅️ Upload a config file in the sidebar to begin.")
        return

    tabs = st.tabs(["📊 Overview", "📋 Article Detail", "⚠️ Gap Analysis", "🔍 Evidence", "📥 Export"])
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
