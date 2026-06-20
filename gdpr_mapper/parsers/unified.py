"""Parser for the native unified YAML security configuration schema."""

from __future__ import annotations
import yaml
from pathlib import Path
from ..models.config_input import SecurityConfig


def parse_unified(source: str | Path) -> SecurityConfig:
    """Load and validate a unified YAML config file."""
    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with path.open() as fh:
        raw = yaml.safe_load(fh)

    if not isinstance(raw, dict):
        raise ValueError(f"Expected a YAML mapping at the top level, got {type(raw).__name__}")

    return SecurityConfig.model_validate(raw)
