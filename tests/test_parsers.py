"""Tests for the three config parsers."""

from __future__ import annotations
import json
import tempfile
from pathlib import Path

import pytest
import yaml

from gdpr_mapper.parsers import parse_unified, parse_azure_nsg, parse_aws_sg
from gdpr_mapper.models.config_input import SecurityConfig


DATA_DIR = Path(__file__).parent.parent / "data" / "sample_configs"


# ---------------------------------------------------------------------------
# Unified YAML parser
# ---------------------------------------------------------------------------

class TestUnifiedParser:
    def test_parse_compliant_sample(self):
        path = DATA_DIR / "sample_compliant.yaml"
        if not path.exists():
            pytest.skip("Sample file not present")
        config = parse_unified(path)
        assert isinstance(config, SecurityConfig)
        assert config.system.name == "Customer Data Platform - Production"
        assert config.firewall.default_ingress == "deny"
        assert config.encryption.at_rest.enabled is True

    def test_parse_gaps_sample(self):
        path = DATA_DIR / "sample_gaps.yaml"
        if not path.exists():
            pytest.skip("Sample file not present")
        config = parse_unified(path)
        assert config.encryption.at_rest.enabled is False
        assert config.access_control.mfa.enabled is False

    def test_parse_minimal_config(self, tmp_path):
        minimal = {"system": {"name": "Minimal"}}
        f = tmp_path / "minimal.yaml"
        f.write_text(yaml.dump(minimal))
        config = parse_unified(f)
        assert config.system.name == "Minimal"
        assert config.encryption.at_rest.enabled is None

    def test_raises_on_missing_file(self):
        with pytest.raises(FileNotFoundError):
            parse_unified("/nonexistent/path/config.yaml")

    def test_raises_on_invalid_yaml_type(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text("- item1\n- item2\n")  # list, not mapping
        with pytest.raises(ValueError, match="Expected a YAML mapping"):
            parse_unified(f)

    def test_parse_partial_encryption(self, tmp_path):
        data = {"encryption": {"at_rest": {"enabled": True, "algorithm": "AES-256"}}}
        f = tmp_path / "enc.yaml"
        f.write_text(yaml.dump(data))
        config = parse_unified(f)
        assert config.encryption.at_rest.enabled is True
        assert config.encryption.at_rest.algorithm == "AES-256"
        assert config.encryption.in_transit.tls_12_minimum is None


# ---------------------------------------------------------------------------
# Azure NSG parser
# ---------------------------------------------------------------------------

class TestAzureNSGParser:
    def test_parse_sample_nsg(self):
        path = DATA_DIR / "azure_nsg_example.json"
        if not path.exists():
            pytest.skip("Sample file not present")
        config = parse_azure_nsg(path)
        assert isinstance(config, SecurityConfig)
        assert "nsg-prod-webapp" in config.system.name
        assert len(config.firewall.rules) > 0

    def test_deny_all_rule_sets_default_deny(self, tmp_path):
        nsg = {
            "name": "test-nsg",
            "securityRules": [
                {
                    "name": "Deny-All",
                    "properties": {
                        "access": "Deny",
                        "direction": "Inbound",
                        "sourceAddressPrefix": "*",
                        "destinationPortRange": "*",
                        "protocol": "*",
                    }
                }
            ],
            "defaultSecurityRules": []
        }
        f = tmp_path / "nsg.json"
        f.write_text(json.dumps(nsg))
        config = parse_azure_nsg(f)
        assert config.firewall.default_ingress == "deny"

    def test_allow_all_rule_infers_default_allow(self, tmp_path):
        nsg = {
            "name": "open-nsg",
            "securityRules": [
                {
                    "name": "AllowAll",
                    "properties": {
                        "access": "Allow",
                        "direction": "Inbound",
                        "sourceAddressPrefix": "*",
                        "destinationPortRange": "*",
                        "protocol": "*",
                    }
                }
            ],
            "defaultSecurityRules": []
        }
        f = tmp_path / "open_nsg.json"
        f.write_text(json.dumps(nsg))
        config = parse_azure_nsg(f)
        assert config.firewall.default_ingress == "allow"

    def test_rules_extracted(self, tmp_path):
        nsg = {
            "name": "my-nsg",
            "securityRules": [
                {
                    "name": "Allow-HTTPS",
                    "properties": {
                        "access": "Allow",
                        "direction": "Inbound",
                        "sourceAddressPrefix": "Internet",
                        "destinationPortRange": "443",
                        "protocol": "TCP",
                    }
                }
            ],
            "defaultSecurityRules": []
        }
        f = tmp_path / "nsg.json"
        f.write_text(json.dumps(nsg))
        config = parse_azure_nsg(f)
        assert len(config.firewall.rules) == 1
        rule = config.firewall.rules[0]
        assert rule.port == "443"
        assert rule.action == "allow"


# ---------------------------------------------------------------------------
# AWS Security Group parser
# ---------------------------------------------------------------------------

class TestAWSSGParser:
    def test_parse_sample_sg(self):
        path = DATA_DIR / "aws_sg_example.json"
        if not path.exists():
            pytest.skip("Sample file not present")
        config = parse_aws_sg(path)
        assert isinstance(config, SecurityConfig)
        assert len(config.firewall.rules) >= 2

    def test_https_only_default_deny(self, tmp_path):
        sg = {
            "SecurityGroups": [{
                "GroupId": "sg-123",
                "GroupName": "https-only",
                "Description": "HTTPS only",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": [],
                        "UserIdGroupPairs": []
                    }
                ]
            }]
        }
        f = tmp_path / "sg.json"
        f.write_text(json.dumps(sg))
        config = parse_aws_sg(f)
        assert config.firewall.default_ingress == "deny"

    def test_all_ports_open_default_allow(self, tmp_path):
        sg = {
            "SecurityGroups": [{
                "GroupId": "sg-open",
                "GroupName": "open",
                "Description": "All open",
                "IpPermissions": [
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": [],
                        "UserIdGroupPairs": []
                    }
                ]
            }]
        }
        f = tmp_path / "open_sg.json"
        f.write_text(json.dumps(sg))
        config = parse_aws_sg(f)
        assert config.firewall.default_ingress == "allow"

    def test_port_range_extracted(self, tmp_path):
        sg = {
            "SecurityGroups": [{
                "GroupId": "sg-range",
                "GroupName": "range-sg",
                "Description": "Port range",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 8000,
                        "ToPort": 8080,
                        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                        "Ipv6Ranges": [],
                        "UserIdGroupPairs": []
                    }
                ]
            }]
        }
        f = tmp_path / "range.json"
        f.write_text(json.dumps(sg))
        config = parse_aws_sg(f)
        assert len(config.firewall.rules) == 1
        assert config.firewall.rules[0].port == "8000-8080"

    def test_empty_sg_raises(self, tmp_path):
        sg = {"SecurityGroups": []}
        f = tmp_path / "empty.json"
        f.write_text(json.dumps(sg))
        with pytest.raises(ValueError, match="No SecurityGroups"):
            parse_aws_sg(f)
