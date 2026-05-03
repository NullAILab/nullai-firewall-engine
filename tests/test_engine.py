"""
test_engine.py — Unit tests for the firewall rule engine.

Covers: model matching, iptables-save parsing, packet simulation,
shadow rule detection, and security audit.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from model import Packet, Rule, Chain, _ip_matches, _port_matches, _proto_matches
from parser import parse_iptables_save, parse_rule_line
from simulator import simulate
from analyzer import find_shadow_rules, audit_security


# ─── Model — IP matching ──────────────────────────────────────────────────────

class TestIpMatches:

    def test_any_matches_all(self):
        assert _ip_matches("1.2.3.4", "any")
        assert _ip_matches("1.2.3.4", "0.0.0.0/0")

    def test_cidr_match(self):
        assert _ip_matches("10.0.0.5", "10.0.0.0/24")

    def test_cidr_no_match(self):
        assert not _ip_matches("192.168.1.1", "10.0.0.0/8")

    def test_exact_host(self):
        assert _ip_matches("10.0.0.1", "10.0.0.1/32")

    def test_invalid_spec_returns_false(self):
        assert not _ip_matches("1.2.3.4", "not-a-cidr")


class TestPortMatches:

    def test_any_matches_all(self):
        assert _port_matches(80, "any")
        assert _port_matches(0, "any")

    def test_exact_port(self):
        assert _port_matches(443, "443")
        assert not _port_matches(80, "443")

    def test_range(self):
        assert _port_matches(1024, "1024:65535")
        assert _port_matches(65535, "1024:65535")
        assert not _port_matches(80, "1024:65535")


class TestProtoMatches:

    def test_all_matches_any_proto(self):
        assert _proto_matches("tcp", "all")
        assert _proto_matches("udp", "all")

    def test_exact_match(self):
        assert _proto_matches("tcp", "tcp")
        assert not _proto_matches("udp", "tcp")

    def test_case_insensitive(self):
        assert _proto_matches("TCP", "tcp")


# ─── Rule.matches ─────────────────────────────────────────────────────────────

class TestRuleMatches:

    def test_default_rule_matches_everything(self):
        rule = Rule()
        pkt = Packet(src_ip="10.0.0.1", dst_ip="192.168.1.1",
                     src_port=50000, dst_port=80, proto="tcp")
        assert rule.matches(pkt)

    def test_restricted_src_matches(self):
        rule = Rule(src="10.0.0.0/24")
        assert rule.matches(Packet(src_ip="10.0.0.5"))

    def test_restricted_src_no_match(self):
        rule = Rule(src="10.0.0.0/24")
        assert not rule.matches(Packet(src_ip="192.168.1.1"))

    def test_dport_match(self):
        rule = Rule(dport="443")
        assert rule.matches(Packet(dst_port=443))
        assert not rule.matches(Packet(dst_port=80))


# ─── Parser ───────────────────────────────────────────────────────────────────

SAMPLE_IPTABLES = """\
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
-A INPUT -j DROP
COMMIT
"""


class TestParser:

    def test_parse_finds_chains(self):
        chains = parse_iptables_save(SAMPLE_IPTABLES)
        assert "INPUT" in chains and "FORWARD" in chains

    def test_chain_policy(self):
        chains = parse_iptables_save(SAMPLE_IPTABLES)
        assert chains["FORWARD"].policy == "DROP"
        assert chains["INPUT"].policy == "ACCEPT"

    def test_rule_count(self):
        chains = parse_iptables_save(SAMPLE_IPTABLES)
        assert len(chains["INPUT"].rules) == 4

    def test_rule_parsed_correctly(self):
        chains = parse_iptables_save(SAMPLE_IPTABLES)
        first = chains["INPUT"].rules[0]
        assert first.src == "10.0.0.0/8"
        assert first.proto == "tcp"
        assert first.dport == "22"
        assert first.target == "ACCEPT"

    def test_empty_input(self):
        assert parse_iptables_save("") == {}

    def test_non_filter_table_ignored(self):
        text = "*nat\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n"
        chains = parse_iptables_save(text)
        assert "PREROUTING" not in chains

    def test_parse_rule_line_direct(self):
        result = parse_rule_line("-A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT")
        assert result is not None
        rule, chain_name = result
        assert chain_name == "INPUT"
        assert rule.src == "192.168.1.0/24"
        assert rule.dport == "22"
        assert rule.target == "ACCEPT"


# ─── Simulator ────────────────────────────────────────────────────────────────

class TestSimulator:

    def _input_chain(self) -> Chain:
        chains = parse_iptables_save(SAMPLE_IPTABLES)
        return chains["INPUT"]

    def test_ssh_from_allowed_range_accepted(self):
        result = simulate(Packet(src_ip="10.0.0.5", dst_port=22, proto="tcp"),
                          self._input_chain())
        assert result.decision == "ACCEPT"
        assert result.rule_index == 0

    def test_http_accepted(self):
        result = simulate(Packet(dst_port=80, proto="tcp"), self._input_chain())
        assert result.decision == "ACCEPT"

    def test_unknown_port_dropped(self):
        result = simulate(Packet(dst_port=9999, proto="tcp"), self._input_chain())
        assert result.decision == "DROP"

    def test_default_policy_when_no_match(self):
        chain = Chain(name="TEST", policy="DROP")
        result = simulate(Packet(), chain)
        assert result.decision == "DROP"
        assert result.rule_index is None

    def test_first_matching_rule_wins(self):
        chain = Chain(name="TEST", policy="DROP", rules=[
            Rule(dport="80", target="ACCEPT"),
            Rule(dport="80", target="DROP"),
        ])
        result = simulate(Packet(dst_port=80), chain)
        assert result.decision == "ACCEPT"
        assert result.rule_index == 0


# ─── Analyzer — shadow rules ──────────────────────────────────────────────────

class TestShadowRules:

    def test_no_shadows_in_clean_chain(self):
        chain = Chain(name="INPUT", policy="DROP", rules=[
            Rule(src="10.0.0.0/8", target="ACCEPT"),
            Rule(src="192.168.0.0/16", target="DROP"),
        ])
        assert find_shadow_rules(chain) == []

    def test_shadow_detected(self):
        # Rule 2 is a subset of rule 1
        chain = Chain(name="INPUT", policy="DROP", rules=[
            Rule(src="10.0.0.0/8",  target="ACCEPT"),
            Rule(src="10.0.1.0/24", target="DROP"),   # shadowed
        ])
        issues = find_shadow_rules(chain)
        assert len(issues) == 1
        assert issues[0].rule_idx == 1

    def test_shadow_severity_is_medium(self):
        chain = Chain(name="INPUT", policy="DROP", rules=[
            Rule(src="0.0.0.0/0", target="ACCEPT"),
            Rule(src="10.0.0.0/8", target="DROP"),
        ])
        issues = find_shadow_rules(chain)
        assert issues[0].severity == "MEDIUM"


# ─── Analyzer — security audit ────────────────────────────────────────────────

class TestAudit:

    def test_ssh_exposed_to_internet_is_high(self):
        chain = Chain(name="INPUT", policy="DROP", rules=[
            Rule(src="0.0.0.0/0", dport="22", proto="tcp", target="ACCEPT"),
        ])
        issues = audit_security(chain)
        assert any(i.severity == "HIGH" and "SSH" in i.description for i in issues)

    def test_telnet_allowed_is_high(self):
        chain = Chain(name="INPUT", policy="DROP", rules=[
            Rule(dport="23", target="ACCEPT"),
        ])
        issues = audit_security(chain)
        assert any("Telnet" in i.description for i in issues)

    def test_default_accept_policy_is_low(self):
        chain = Chain(name="FORWARD", policy="ACCEPT")
        issues = audit_security(chain)
        assert any(i.severity == "LOW" and "ACCEPT" in i.description for i in issues)

    def test_clean_chain_no_issues(self):
        chain = Chain(name="INPUT", policy="DROP", rules=[
            Rule(src="10.0.0.0/8", dport="22", proto="tcp", target="ACCEPT"),
            Rule(dport="80",  proto="tcp", target="ACCEPT"),
            Rule(dport="443", proto="tcp", target="ACCEPT"),
        ])
        # SSH restricted to 10/8, no Telnet, DROP policy — should be clean
        issues = audit_security(chain)
        ssh_issues = [i for i in issues if "SSH" in i.description]
        assert len(ssh_issues) == 0
