"""
Parser for AWS Security Group JSON output.

Accepts the JSON produced by:
    aws ec2 describe-security-groups --group-ids <sg-id> --output json

Only ingress/egress rules are extractable. All other SecurityConfig sections
remain at defaults (not assessed).
"""

from __future__ import annotations
import json
from pathlib import Path
from ..models.config_input import SecurityConfig, FirewallConfig, FirewallRule, SystemInfo


_OPEN_CIDR = {"0.0.0.0/0", "::/0"}


def parse_aws_sg(source: str | Path) -> SecurityConfig:
    """Parse an AWS describe-security-groups JSON export into a SecurityConfig."""
    path = Path(source)
    with path.open() as fh:
        data = json.load(fh)

    groups = data.get("SecurityGroups", [data])
    if not groups:
        raise ValueError("No SecurityGroups found in JSON")

    sg = groups[0]
    name = sg.get("GroupName", sg.get("GroupId", "AWS Security Group"))
    description = sg.get("Description", "")
    rules: list[FirewallRule] = []

    for perm in sg.get("IpPermissions", []):
        proto = perm.get("IpProtocol", "*")
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")

        if proto == "-1":
            port_str = "*"
            proto = "*"
        elif from_port == to_port:
            port_str = str(from_port) if from_port is not None else "*"
        else:
            port_str = f"{from_port}-{to_port}" if from_port is not None else "*"

        sources = [r["CidrIp"] for r in perm.get("IpRanges", [])]
        sources += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])]
        sources += [r["GroupId"] for r in perm.get("UserIdGroupPairs", [])]
        if not sources:
            sources = ["*"]

        for src in sources:
            rules.append(
                FirewallRule(
                    protocol=proto.upper(),
                    port=port_str,
                    source=src,
                    action="allow",
                    direction="inbound",
                )
            )

    has_open_all = any(
        r.source in _OPEN_CIDR and r.port == "*" and r.direction == "inbound" for r in rules
    )
    default_ingress = "allow" if has_open_all else "deny"

    fw = FirewallConfig(
        default_ingress=default_ingress,
        rules=rules,
        network_segmentation=None,
    )

    return SecurityConfig(
        system=SystemInfo(
            name=name,
            description=f"AWS Security Group — {description}",
            environment="unknown",
        ),
        firewall=fw,
    )
