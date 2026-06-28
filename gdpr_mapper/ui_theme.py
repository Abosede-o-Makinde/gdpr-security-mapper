"""Shared Streamlit UI styling — offline-safe SVG icons and status badges."""

from __future__ import annotations

import streamlit as st

from gdpr_mapper.models.compliance import ComplianceStatus

_STATUS_COLOUR = {
    ComplianceStatus.SATISFIED: "#2E7D32",
    ComplianceStatus.PARTIAL: "#F57F17",
    ComplianceStatus.GAP: "#B71C1C",
    ComplianceStatus.NA: "#78909C",
}

# Material-style paths (Apache 2.0) — inlined so the dashboard works without CDN access.
_ICON_PATHS: dict[str, str] = {
    "shield": (
        "M12 1 3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18 "
        "7 3.11v4.71c0 4.52-3.07 8.86-7 9.93-3.93-1.07-7-5.41-7-9.93V6.29l7-3.11z"
    ),
    "data_object": (
        "M4 2h16v2H4V2zm0 4h10v2H4V6zm0 4h16v2H4v-2zm0 4h10v2H4v-2zm0 4h16v2H4v-2z"
    ),
    "description": (
        "M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 "
        "16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"
    ),
}

_THEME_INJECTED = False


def inject_theme() -> None:
    global _THEME_INJECTED
    if _THEME_INJECTED:
        return
    st.markdown(
        """
        <style>
          .ui-icon {
            display: inline-block;
            vertical-align: middle;
            flex-shrink: 0;
          }
          .app-title {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 1.5rem;
            font-weight: 600;
            margin: 0 0 0.25rem 0;
            line-height: 1.3;
          }
          .status-pill {
            display: inline-block;
            padding: 0.15rem 0.55rem;
            border-radius: 4px;
            font-size: 0.85rem;
            font-weight: 600;
            letter-spacing: 0.02em;
          }
          .landing-lead { font-size: 1.05rem; color: #424242; margin-bottom: 1rem; }
          div[data-testid="stSidebar"] .stButton > button { font-weight: 500; }
        </style>
        """,
        unsafe_allow_html=True,
    )
    _THEME_INJECTED = True


def icon(name: str, size: int = 20, color: str = "currentColor") -> str:
    path = _ICON_PATHS.get(name)
    if path is None:
        return ""
    return (
        f'<svg class="ui-icon" width="{size}" height="{size}" viewBox="0 0 24 24" '
        f'fill="{color}" aria-hidden="true" role="img">'
        f"<path d=\"{path}\"/>"
        f"</svg>"
    )


def app_title_html(text: str = "GDPR Security Mapper", size: int = 28) -> str:
    return f'<div class="app-title">{icon("shield", size, "#1565C0")} {text}</div>'


def status_badge(status: ComplianceStatus) -> str:
    colour = _STATUS_COLOUR[status]
    return (
        f'<span class="status-pill" style="background:{colour}18;color:{colour};'
        f'border:1px solid {colour}40">{status.value}</span>'
    )


def status_text(status: ComplianceStatus) -> str:
    return status.value
