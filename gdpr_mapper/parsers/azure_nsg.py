"""
Parser for Azure Network Security Group JSON output.

Accepts the JSON produced by:
    az network nsg show --resource-group <rg> --name <nsg> -o json

Only firewall/network controls are extractable from an NSG. The rest of the
SecurityConfig is left at defaults (all Optional → None = 'not assessed').
"""

from __future__ import annotations
import json
from pathlib import Path
from ..models.config_input import SecurityConfig, FirewallConfig, FirewallRule, SystemInfo


_INTERNET_SOURCES = {"Internet", "0.0.0.0/0", "*", "Any"}
_RISKY_PORTS = {22, 23, 3389, 5985, 5986, 3306, 5432, 1433, 27017, 6379, 9200, 2375, 2376}


def parse_azure_nsg(source: str | Path) -> SecurityConfig:
    """Parse an Azure NSG JSON export into a SecurityConfig."""
    path = Path(source)
    with path.open() as fh:
        nsg = json.load(fh)

    name = nsg.get("name", "Azure NSG")
    rules: list[FirewallRule] = []
    has_explicit_deny_all = False

    for rule in nsg.get("securityRules", []) + nsg.get("defaultSecurityRules", []):
        props = rule.get("properties", rule)
        action = "allow" if props.get("access", "").lower() == "allow" else "deny"
        direction = "inbound" if props.get("direction", "").lower() == "inbound" else "outbound"
        src = props.get("sourceAddressPrefix", "*")
        dst_port = props.get("destinationPortRange", "*")
        proto = props.get("protocol", "*").upper()

        if action == "deny" and dst_port == "*" and src in ("*", "Any"):
            has_explicit_deny_all = True

        rules.append(
            FirewallRule(
                name=rule.get("name", ""),
                protocol=proto,
                port=dst_port,
                source=src,
                action=action,
                direction=direction,
            )
        )

    default_ingress = "deny" if has_explicit_deny_all else _infer_default(rules, "inbound")

    fw = FirewallConfig(
        default_ingress=default_ingress,
        rules=rules,
        network_segmentation=True,  # NSGs imply segmentation exists
    )

    return SecurityConfig(
        system=SystemInfo(
            name=name,
            description=f"Imported from Azure NSG: {name}",
            environment="unknown",
        ),
        firewall=fw,
    )


def _infer_default(rules: list[FirewallRule], direction: str) -> str:
    """Heuristic: if any allow-all inbound rule exists with Internet source, treat as allow."""
    for r in rules:
        if r.direction == direction and r.action == "allow" and r.source in _INTERNET_SOURCES:
            if r.port == "*":
                return "allow"
    return "deny"
