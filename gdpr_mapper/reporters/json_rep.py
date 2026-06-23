"""JSON reporter — serialises the full ComplianceReport to file or stdout."""

from __future__ import annotations
import json
import sys
from pathlib import Path

from ..models.compliance import ComplianceReport


class JsonReporter:
    def __init__(self, output: str | Path | None = None, indent: int = 2) -> None:
        self.output = Path(output) if output else None
        self.indent = indent

    def render(self, report: ComplianceReport) -> None:
        payload = json.dumps(report.to_dict(), indent=self.indent, ensure_ascii=False)
        if self.output:
            self.output.write_text(payload, encoding="utf-8")
        else:
            sys.stdout.write(payload + "\n")
